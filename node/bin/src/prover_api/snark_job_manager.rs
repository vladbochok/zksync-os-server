use crate::prover_api::fri_job_manager::FriJob;
use crate::prover_api::metrics::{ProverStage, ProverType};
use crate::prover_api::prover_job_map::ProverJobMap;
use crate::prover_api::zisk_data_cache::ZiskDataCache;
use crate::prover_api::zisk_job_manager::{ZiskJobData, ZiskJobManager};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use zksync_os_l1_sender::batcher_metrics::BatchExecutionStage;
use zksync_os_l1_sender::batcher_model::{
    FriProof, RealSnarkProof, SignedBatchEnvelope, SnarkProof,
};
use zksync_os_l1_sender::commands::prove::ProofCommand;
use zksync_os_observability::{
    ComponentStateHandle, ComponentStateReporter, GenericComponentState,
};
use zksync_os_types::ProvingVersion;

/// Job manager for SNARK proving.
///
/// When an Airbender SNARK is submitted and ZiSK data exists for the batch,
/// the batch is routed to `ZiskJobManager` for multi-proof composition.
/// Otherwise, the Airbender-only proof is sent downstream immediately.
pub struct SnarkJobManager {
    jobs: ProverJobMap<FriProof>,
    prove_batches_sender: Sender<ProofCommand>,
    max_fris_per_snark: usize,
    zisk_data_cache: Option<Arc<ZiskDataCache>>,
    zisk_job_manager: Option<Arc<ZiskJobManager>>,
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
            zisk_data_cache: None,
            zisk_job_manager: None,
            latency_tracker,
        }
    }

    /// Set the ZiSK data cache for multi-proof composition.
    pub fn set_zisk_data_cache(&mut self, cache: Arc<ZiskDataCache>) {
        self.zisk_data_cache = Some(cache);
    }

    /// Set the ZiSK job manager for routing Airbender SNARKs to multi-proof composition.
    pub fn set_zisk_job_manager(&mut self, zjm: Arc<ZiskJobManager>) {
        self.zisk_job_manager = Some(zjm);
    }

    /// Get a reference to the downstream proof command sender.
    /// Used by ZiskJobManager to share the same downstream channel.
    pub fn prove_sender(&self) -> &Sender<ProofCommand> {
        &self.prove_batches_sender
    }

    /// Adds a pending job to the SNARK proving queue.
    /// Awaits if queue is full (ProverJobMap.max_assigned_batch_range).
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

        let has_zisk = if let Some(ref cache) = self.zisk_data_cache {
            cache.contains(batch_from).await
        } else {
            false
        };

        if has_zisk {
            let zjm = self.zisk_job_manager.as_ref()
                .expect("zisk_job_manager must be set when zisk_data_cache is set");
            // Atomic remove — avoids TOCTOU race between contains() and remove().
            let Some(zisk_data) = self.zisk_data_cache.as_ref().unwrap().remove(batch_from).await else {
                // Another concurrent submit_proof consumed it. Treat as no-ZiSK batch.
                tracing::warn!(batch = batch_from, "ZiSK data consumed by concurrent submit, sending Airbender-only");
                let consumed_batches_proven: Vec<_> = consumed_batches_proven
                    .into_iter()
                    .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
                    .collect();
                return self.send_downstream(ProofCommand::new(
                    consumed_batches_proven,
                    SnarkProof::Real(RealSnarkProof::V2 {
                        proof: payload,
                        proving_execution_version: proving_version as u32,
                    }),
                )).await;
            };

            let batches: Vec<_> = consumed_batches_proven
                .into_iter()
                .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
                .collect();

            tracing::info!(
                batch = batch_from,
                era_proof_bytes = payload.len(),
                zisk_data_bytes = zisk_data.len(),
                "Airbender SNARK received, routing to ZiSK job manager"
            );

            zjm.add_job(batch_from, ZiskJobData {
                zisk_data,
                era_proof: payload,
                proving_execution_version: proving_version as u32,
                batches,
            }).await;
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

}

const POLL_INTERVAL_MS: u64 = 1000;

pub struct FakeSnarkProver {
    job_manager: Arc<SnarkJobManager>,
    max_batch_age: Duration,
    polling_interval: Duration,
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


