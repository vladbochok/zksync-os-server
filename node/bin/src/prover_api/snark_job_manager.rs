use crate::prover_api::fri_job_manager::{FriJob, FriJobManager};
use crate::prover_api::metrics::{ProverStage, ProverType};
use crate::prover_api::prover_job_map::ProverJobMap;
use crate::prover_api::zisk_prover::ZiskProver;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use zksync_os_l1_sender::batcher_metrics::BatchExecutionStage;
use zksync_os_l1_sender::batcher_model::{
    FriProof, MultiProofSnarkProof, RealSnarkProof, SignedBatchEnvelope, SnarkProof,
};
use zksync_os_l1_sender::commands::prove::ProofCommand;
use zksync_os_observability::{
    ComponentStateHandle, ComponentStateReporter, GenericComponentState,
};
use zksync_os_types::ProvingVersion;

/// Cached Airbender SNARK proof waiting for ZiSK SNARK to be generated.
struct PendingMultiProof {
    era_proof: Vec<u8>,
    proving_version: u32,
    batches: Vec<SignedBatchEnvelope<FriProof>>,
}

/// Job manager for SNARK proving.
///
/// When an Airbender SNARK is submitted and ZiSK data exists for the batch,
/// the proof is cached. A background task (`MultiProofCombiner`) generates
/// the ZiSK SNARK and combines both into a MultiProof for L1 submission.
pub struct SnarkJobManager {
    jobs: ProverJobMap<FriProof>,
    prove_batches_sender: Sender<ProofCommand>,
    max_fris_per_snark: usize,
    fri_job_manager: Option<Arc<FriJobManager>>,
    /// Airbender SNARKs waiting for ZiSK SNARK generation.
    pending_multi_proofs: Mutex<HashMap<u64, PendingMultiProof>>,
    latency_tracker: ComponentStateHandle<GenericComponentState>,
}

impl SnarkJobManager {
    pub fn new(
        prove_batches_sender: Sender<ProofCommand>,
        max_fris_per_snark: usize,
        assignment_timeout: Duration,
        max_assigned_batch_range: usize,
    ) -> Self {
        let jobs = ProverJobMap::<FriProof>::new(
            assignment_timeout,
            max_assigned_batch_range,
            ProverStage::Snark,
        );
        let latency_tracker = ComponentStateReporter::global().handle_for(
            "snark_job_manager",
            GenericComponentState::ProcessingOrWaitingRecv,
        );
        Self {
            jobs,
            prove_batches_sender,
            max_fris_per_snark,
            fri_job_manager: None,
            pending_multi_proofs: Mutex::new(HashMap::new()),
            latency_tracker,
        }
    }

    pub fn set_fri_job_manager(&mut self, fjm: Arc<FriJobManager>) {
        self.fri_job_manager = Some(fjm);
    }

    pub async fn add_job(&self, batch_envelope: SignedBatchEnvelope<FriProof>) {
        self.jobs.add_job(batch_envelope).await
    }

    pub async fn pick_real_job(
        &self,
        prover_id: String,
    ) -> anyhow::Result<Option<Vec<(FriJob, FriProof)>>> {
        self.process_pending_fake_fri_proofs().await?;

        let batches_with_real_proofs = self
            .jobs
            .pick_jobs_while_with_limit(self.max_fris_per_snark, &prover_id, |job| {
                !job.batch_envelope.data.is_fake()
            })
            .await;

        if batches_with_real_proofs.is_empty() {
            tracing::trace!(prover_id, "no SNARK prove jobs are available for pick up");
            return Ok(None);
        }

        Ok(Some(batches_with_real_proofs))
    }

    /// Submit a real Airbender SNARK proof.
    ///
    /// If ZiSK data exists, the Airbender SNARK is cached for async combination.
    /// If no ZiSK data exists, the Airbender proof is sent downstream immediately.
    pub async fn submit_proof(
        &self,
        batch_from: u64,
        batch_to: u64,
        proving_version: ProvingVersion,
        payload: Vec<u8>,
        prover_id: String,
    ) -> anyhow::Result<()> {
        let Some(consumed_batches_proven) = self
            .jobs
            .complete_many_jobs(batch_from, batch_to, ProverType::Real, &prover_id)
            .await
        else {
            anyhow::bail!("race condition: some batches were completed earlier")
        };

        let server_vk = consumed_batches_proven[0]
            .batch
            .verification_key_hash()
            .expect("verification key hash must be present as it was set by server");
        let prover_vk = proving_version.vk_hash();
        anyhow::ensure!(
            server_vk == prover_vk,
            "Verification key hash mismatch: server got {server_vk}, prover got {prover_vk}"
        );

        let has_zisk = if let Some(ref fjm) = self.fri_job_manager {
            fjm.peek_zisk_data(batch_from).await
        } else {
            false
        };

        if has_zisk {
            tracing::info!(
                batch = batch_from,
                era_proof_bytes = payload.len(),
                "Airbender SNARK received, queuing for ZiSK combination"
            );
            let batches: Vec<_> = consumed_batches_proven
                .into_iter()
                .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
                .collect();
            self.pending_multi_proofs.lock().await.insert(
                batch_from,
                PendingMultiProof {
                    era_proof: payload,
                    proving_version: proving_version as u32,
                    batches,
                },
            );
            Ok(())
        } else {
            let consumed_batches_proven: Vec<_> = consumed_batches_proven
                .into_iter()
                .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
                .collect();
            self.send_downstream(ProofCommand::new(
                consumed_batches_proven,
                SnarkProof::Real(RealSnarkProof::V2 {
                    proof: payload,
                    proving_execution_version: proving_version as u32,
                }),
            ))
            .await?;
            Ok(())
        }
    }

    /// Process one pending multi-proof: generate ZiSK SNARK and combine.
    /// Called by the MultiProofCombiner background task.
    ///
    /// Atomically removes the pending entry to prevent concurrent processing.
    /// On failure, re-inserts the entry for retry.
    async fn process_one_pending_multi_proof(
        &self,
        zisk_prover: &ZiskProver,
    ) -> anyhow::Result<bool> {
        // Atomically take the first pending batch.
        let (batch_num, pending) = {
            let mut map = self.pending_multi_proofs.lock().await;
            let Some(&batch_num) = map.keys().next() else {
                return Ok(false);
            };
            // Remove to prevent concurrent processing. Re-insert on failure.
            let pending = map.remove(&batch_num).unwrap();
            (batch_num, pending)
        };

        // Clone ZiSK data (preserve original for retry).
        let zisk_bincode = if let Some(ref fjm) = self.fri_job_manager {
            fjm.clone_zisk_data(batch_num).await
        } else {
            None
        };

        let Some(zisk_bincode) = zisk_bincode else {
            // Re-insert for retry.
            self.pending_multi_proofs
                .lock()
                .await
                .insert(batch_num, pending);
            anyhow::bail!("ZiSK data missing for batch {batch_num}");
        };

        tracing::info!(
            batch = batch_num,
            zisk_input_bytes = zisk_bincode.len(),
            "Generating ZiSK SNARK for multi-proof"
        );

        let prover = zisk_prover.clone();
        let zisk_result = tokio::task::spawn_blocking(move || {
            prover.generate_proof(&zisk_bincode, batch_num)
        })
        .await
        .map_err(|e| anyhow::anyhow!("ZiSK spawn_blocking join error: {e}"))?;

        match zisk_result {
            Ok(output) => {
                // Success — remove ZiSK data from cache.
                if let Some(ref fjm) = self.fri_job_manager {
                    fjm.take_zisk_data(batch_num).await;
                }

                tracing::info!(batch = batch_num, "Combined Airbender + ZiSK multi-proof ready");
                let snark_proof = SnarkProof::MultiProof(MultiProofSnarkProof {
                    era_proof: pending.era_proof,
                    zisk_proof: output.proof,
                    zisk_public_values: output.public_values,
                    proving_execution_version: pending.proving_version,
                });
                self.send_downstream(ProofCommand::new(pending.batches, snark_proof))
                    .await?;
                Ok(true)
            }
            Err(e) => {
                tracing::error!(batch = batch_num, "ZiSK SNARK failed: {e:#}");
                // Re-insert for retry.
                self.pending_multi_proofs
                    .lock()
                    .await
                    .insert(batch_num, pending);
                Err(e.into())
            }
        }
    }

    async fn process_pending_fake_fri_proofs(&self) -> anyhow::Result<()> {
        self.process_pending_fake_or_timed_out_fri_proofs(None)
            .await
    }

    async fn process_pending_fake_or_timed_out_fri_proofs(
        &self,
        timeout_for_real_fris: Option<Duration>,
    ) -> anyhow::Result<()> {
        loop {
            let assigned: Vec<(FriJob, FriProof)> = self
                .jobs
                .pick_jobs_while_with_limit(self.max_fris_per_snark, "fake_prover", |job| {
                    job.batch_envelope.data.is_fake()
                        || timeout_for_real_fris
                            .is_some_and(|t| job.metadata.added_at.elapsed() >= t)
                })
                .await;

            if assigned.is_empty() {
                return Ok(());
            }

            let real_proofs_count = assigned
                .iter()
                .filter(|(_, proof)| !proof.is_fake())
                .count();
            if let (Some(first), Some(last)) = (assigned.first(), assigned.last()) {
                tracing::info!(
                    from_batch = first.0.batch_number,
                    to_batch = last.0.batch_number,
                    real_proofs_count,
                    fake_proofs_count = assigned.len() - real_proofs_count,
                    "consuming proofs for fake SNARKing"
                );
            }

            let mut completed = Vec::default();
            for (job, _) in assigned {
                if let Some(envelope) = self
                    .jobs
                    .complete_job(job.batch_number, ProverType::Fake, "fake_prover")
                    .await
                {
                    completed.push(envelope);
                }
            }

            let batches_with_fake_proofs = completed
                .into_iter()
                .map(|batch| batch.with_stage(BatchExecutionStage::SnarkProvedFake))
                .collect();

            self.send_downstream(ProofCommand::new(batches_with_fake_proofs, SnarkProof::Fake))
                .await?;
        }
    }

    async fn send_downstream(&self, proof_command: ProofCommand) -> anyhow::Result<()> {
        self.latency_tracker
            .enter_state(GenericComponentState::WaitingSend);
        self.prove_batches_sender.send(proof_command).await?;
        self.latency_tracker
            .enter_state(GenericComponentState::ProcessingOrWaitingRecv);
        Ok(())
    }

    /// Check if there are pending multi-proofs.
    pub async fn has_pending_multi_proofs(&self) -> bool {
        !self.pending_multi_proofs.lock().await.is_empty()
    }
}

const POLL_INTERVAL_MS: u64 = 1000;

pub struct FakeSnarkProver {
    job_manager: Arc<SnarkJobManager>,
    max_batch_age: Duration,
    polling_interval: Duration,
}

/// Background task that generates ZiSK SNARK proofs and combines them
/// with cached Airbender SNARKs into MultiProofs.
///
/// When `gpu_coordinator` is set, acquires the GPU lock before running
/// ZiSK and releases it after, enabling sequential GPU sharing with
/// the Airbender prover.
pub struct MultiProofCombiner {
    job_manager: Arc<SnarkJobManager>,
    zisk_prover: ZiskProver,
    gpu_coordinator: Option<Arc<crate::prover_api::gpu_orchestrator::GpuCoordinator>>,
    polling_interval: Duration,
    retry_delay: Duration,
}

impl FakeSnarkProver {
    pub fn new(job_manager: Arc<SnarkJobManager>, max_batch_age: Duration) -> Self {
        Self {
            job_manager,
            max_batch_age,
            polling_interval: Duration::from_millis(POLL_INTERVAL_MS),
        }
    }

    pub async fn run(self) {
        loop {
            tokio::time::sleep(self.polling_interval).await;
            if let Err(e) = self
                .job_manager
                .process_pending_fake_or_timed_out_fri_proofs(Some(self.max_batch_age))
                .await
            {
                tracing::error!("FakeSnarkProver error (will retry): {e:#}");
            }
        }
    }
}

impl MultiProofCombiner {
    pub fn new(
        job_manager: Arc<SnarkJobManager>,
        zisk_prover: ZiskProver,
        gpu_coordinator: Option<Arc<crate::prover_api::gpu_orchestrator::GpuCoordinator>>,
    ) -> Self {
        Self {
            job_manager,
            zisk_prover,
            gpu_coordinator,
            polling_interval: Duration::from_millis(POLL_INTERVAL_MS),
            retry_delay: Duration::from_secs(60),
        }
    }

    pub async fn run(self) {
        loop {
            if !self.job_manager.has_pending_multi_proofs().await {
                tokio::time::sleep(self.polling_interval).await;
                continue;
            }

            // Acquire GPU if coordinator is present (waits for Airbender to exit).
            if let Some(ref coord) = self.gpu_coordinator {
                tracing::info!("MultiProofCombiner: waiting for GPU");
                coord.acquire_gpu_for_zisk().await;
                tracing::info!("MultiProofCombiner: GPU acquired");
            }

            // Process all pending proofs while we hold the GPU.
            loop {
                match self
                    .job_manager
                    .process_one_pending_multi_proof(&self.zisk_prover)
                    .await
                {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::error!("MultiProofCombiner error (retry in {:?}): {e:#}", self.retry_delay);
                        break;
                    }
                }
            }

            // Release GPU.
            if let Some(ref coord) = self.gpu_coordinator {
                coord.release_gpu_from_zisk().await;
                tracing::info!("MultiProofCombiner: GPU released");
            }
        }
    }
}

