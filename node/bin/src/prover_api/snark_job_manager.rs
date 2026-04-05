use crate::prover_api::fri_job_manager::{FriJob, FriJobManager};
use crate::prover_api::metrics::{ProverStage, ProverType};
use crate::prover_api::prover_job_map::ProverJobMap;
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
    /// The MultiProofCombiner background task will generate the ZiSK SNARK and
    /// send the combined MultiProof downstream.
    ///
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
            .expect("verification key hash must be present");
        let prover_vk = proving_version.vk_hash();
        anyhow::ensure!(
            server_vk == prover_vk,
            "Verification key hash mismatch: server got {server_vk}, prover got {prover_vk}"
        );

        // Check if ZiSK data exists — if so, cache for async combination.
        let has_zisk = if let Some(ref fjm) = self.fri_job_manager {
            fjm.peek_zisk_data(batch_from).await
        } else {
            false
        };

        if has_zisk {
            tracing::info!(
                batch = batch_from,
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
            // No ZiSK data — send Airbender-only proof immediately.
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
    async fn process_one_pending_multi_proof(&self) -> anyhow::Result<bool> {
        // Peek at the first pending batch without removing it.
        let batch_num = {
            let map = self.pending_multi_proofs.lock().await;
            match map.keys().next().copied() {
                Some(k) => k,
                None => return Ok(false),
            }
        };

        // Clone ZiSK data (don't remove — we may need to retry on failure).
        let zisk_bincode = if let Some(ref fjm) = self.fri_job_manager {
            fjm.clone_zisk_data(batch_num).await
        } else {
            None
        };

        let Some(zisk_bincode) = zisk_bincode else {
            anyhow::bail!("ZiSK data missing for batch {batch_num} — cannot produce multi-proof");
        };

        tracing::info!(
            batch = batch_num,
            zisk_input_bytes = zisk_bincode.len(),
            "Generating ZiSK SNARK for multi-proof"
        );
        let zisk_result = tokio::task::spawn_blocking(move || {
            generate_zisk_snark_proof(&zisk_bincode, batch_num)
        })
        .await
        .map_err(|e| anyhow::anyhow!("ZiSK spawn_blocking: {e}"))?;

        let (zisk_proof, zisk_public_values) = zisk_result
            .map_err(|e| anyhow::anyhow!("ZiSK SNARK failed for batch {batch_num}: {e}"))?;

        // ZiSK SNARK succeeded — remove both the pending proof and ZiSK data.
        let pending = self
            .pending_multi_proofs
            .lock()
            .await
            .remove(&batch_num)
            .expect("pending multi-proof disappeared");
        if let Some(ref fjm) = self.fri_job_manager {
            fjm.take_zisk_data(batch_num).await;
        }

        tracing::info!(batch = batch_num, "Combined Airbender + ZiSK multi-proof ready");
        let snark_proof = SnarkProof::MultiProof(MultiProofSnarkProof {
            era_proof: pending.era_proof,
            zisk_proof,
            zisk_public_values,
            proving_execution_version: pending.proving_version,
        });

        self.send_downstream(ProofCommand::new(pending.batches, snark_proof))
            .await?;
        Ok(true)
    }

    /// Consumes fake FRI proofs from the head of the queue and turns them into fake SNARKs.
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
                        || (timeout_for_real_fris.is_some()
                            && job.metadata.added_at.elapsed() >= timeout_for_real_fris.unwrap())
                })
                .await;

            if assigned.is_empty() {
                return Ok(());
            }
            let real_proofs_count = assigned
                .iter()
                .filter(|(_, proof)| !proof.is_fake())
                .count();
            tracing::info!(
                "consuming fake proofs for SNARKing for batches {}-{} ({} real proofs; {} fake proofs)",
                assigned.first().unwrap().0.batch_number,
                assigned.last().unwrap().0.batch_number,
                real_proofs_count,
                assigned.len() - real_proofs_count,
            );

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

/// Background task that generates ZiSK SNARK proofs and combines them
/// with cached Airbender SNARKs into MultiProofs.
pub struct MultiProofCombiner {
    job_manager: Arc<SnarkJobManager>,
    polling_interval: Duration,
}

/// Generate a real ZiSK SNARK proof by running the full GPU-accelerated pipeline.
/// Uses `cargo-zisk prove --snark` for combined STARK aggregation + SNARK wrapping.
/// Returns (snark_proof_bytes[768], public_values[256]).
fn generate_zisk_snark_proof(
    zisk_bincode: &[u8],
    batch_number: u64,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::process::Command;

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let zisk_bin = format!("{home}/.zisk/bin");
    let elf_path = format!(
        "{home}/zksync-os-second-proof-system/zksync-os-zisk/guest/target/riscv64ima-zisk-zkvm-elf/release/zksync-os-zisk-guest"
    );
    let proving_key = format!("{home}/.zisk/provingKey");
    let snark_key = format!("{home}/.zisk/provingKeySnark");

    let work_dir = format!("/tmp/zisk_prove_batch_{batch_number}");
    let _ = std::fs::create_dir_all(&work_dir);

    // Write ZiSK stdin format: [len:u64_LE][bincode][padding]
    let input_path = format!("{work_dir}/input.bin");
    {
        let len = zisk_bincode.len() as u64;
        let mut buf = Vec::with_capacity(8 + zisk_bincode.len() + 8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(zisk_bincode);
        let total = 8 + zisk_bincode.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat(0u8).take(padding));
        std::fs::write(&input_path, &buf).map_err(|e| format!("write input: {e}"))?;
    }

    // STARK aggregation (GPU-accelerated)
    let stark_dir = format!("{work_dir}/stark");
    let _ = std::fs::create_dir_all(format!("{stark_dir}/proofs"));
    tracing::info!(batch_number, "Running ZiSK STARK aggregation (GPU)...");
    let stark_output = Command::new(format!("{zisk_bin}/cargo-zisk"))
        .args([
            "prove", "-e", &elf_path, "-i", &input_path, "-k", &proving_key, "-o", &stark_dir,
            "--emulator", "--aggregation", "--save-proofs", "-v",
        ])
        .output()
        .map_err(|e| format!("cargo-zisk prove: {e}"))?;
    if !stark_output.status.success() {
        let stderr = String::from_utf8_lossy(&stark_output.stderr);
        return Err(format!(
            "STARK aggregation failed: {}",
            &stderr[stderr.len().saturating_sub(1000)..]
        ));
    }
    let vadcop_path = format!("{stark_dir}/vadcop_final_proof.bin");
    if !std::path::Path::new(&vadcop_path).exists() {
        return Err("vadcop_final_proof.bin not generated".into());
    }

    // SNARK wrapping
    let snark_dir = format!("{work_dir}/snark");
    let _ = std::fs::create_dir_all(&snark_dir);
    tracing::info!(batch_number, "Running ZiSK SNARK wrapping...");
    let snark_output = Command::new(format!("{zisk_bin}/cargo-zisk"))
        .args([
            "prove-snark", "--proof", &vadcop_path, "--elf", &elf_path,
            "--proving-key-snark", &snark_key, "-o", &snark_dir, "-v",
        ])
        .output()
        .map_err(|e| format!("cargo-zisk prove-snark: {e}"))?;
    if !snark_output.status.success() {
        let stderr = String::from_utf8_lossy(&snark_output.stderr);
        return Err(format!(
            "SNARK wrapping failed: {}",
            &stderr[stderr.len().saturating_sub(1000)..]
        ));
    }

    let snark_proof_path = format!("{snark_dir}/final_snark_proof.bin");
    if !std::path::Path::new(&snark_proof_path).exists() {
        return Err("final_snark_proof.bin not generated".into());
    }

    // Parse output: [proof_len:u64_LE][proof_bytes][pv_len:u64_LE][pv_bytes]
    let data = std::fs::read(&snark_proof_path).map_err(|e| format!("read SNARK: {e}"))?;
    let proof_len = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    if proof_len != 768 {
        return Err(format!("unexpected proof length: {proof_len}, expected 768"));
    }
    let snark_proof_bytes = data[8..8 + 768].to_vec();
    let pv_offset = 8 + 768;
    let pv_len = u64::from_le_bytes(data[pv_offset..pv_offset + 8].try_into().unwrap()) as usize;
    if pv_len != 256 {
        return Err(format!(
            "unexpected public values length: {pv_len}, expected 256"
        ));
    }
    let public_values = data[pv_offset + 8..pv_offset + 8 + 256].to_vec();

    tracing::info!(batch_number, work_dir, "ZiSK SNARK proof generated");
    Ok((snark_proof_bytes, public_values))
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
    pub fn new(job_manager: Arc<SnarkJobManager>) -> Self {
        Self {
            job_manager,
            polling_interval: Duration::from_millis(POLL_INTERVAL_MS),
        }
    }

    pub async fn run(self) {
        loop {
            match self.job_manager.process_one_pending_multi_proof().await {
                Ok(true) => {
                    // Processed one — check for more immediately.
                    continue;
                }
                Ok(false) => {
                    // Nothing pending — sleep before polling again.
                    tokio::time::sleep(self.polling_interval).await;
                }
                Err(e) => {
                    tracing::error!("MultiProofCombiner error (will retry in 60s): {e:#}");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }
    }
}
