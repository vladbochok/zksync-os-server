use crate::prover_api::fri_job_manager::{FriJob, FriJobManager};
use crate::prover_api::metrics::{ProverStage, ProverType};
use crate::prover_api::prover_job_map::ProverJobMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use zksync_os_l1_sender::batcher_metrics::BatchExecutionStage;
use zksync_os_l1_sender::batcher_model::{
    FriProof, RealSnarkProof, SignedBatchEnvelope, SnarkProof, TwoProofSystemSnarkProof,
};
use zksync_os_l1_sender::commands::prove::ProofCommand;
use zksync_os_observability::{
    ComponentStateHandle, ComponentStateReporter, GenericComponentState,
};
use zksync_os_types::ProvingVersion;

/// Job manager for SNARK proving.
///
/// Supports multiple SNARK provers
///
/// Supports both real and fake proofs.
///  - Fake FRI proofs always result in fake SNARK proofs.
///  - Real FRI proofs may result in real or fake SNARK proofs depending on prover availability
///
/// `SnarkJobManager` aims to assign real prover jobs to real SNARK provers -
///     but if jobs are not picked within a timeout (`max_batch_age`), it releases it to a fake prover
///
///
/// `ComponentStateLatencyTracker`: Only tracks `Processing` / `WaitingSend` states
pub struct SnarkJobManager {
    // == state ==
    jobs: ProverJobMap<FriProof>,
    // outbound
    prove_batches_sender: Sender<ProofCommand>,
    // config
    max_fris_per_snark: usize,
    /// Reference to FriJobManager for accessing cached ZiSK data.
    #[allow(dead_code)]
    fri_job_manager: Option<Arc<FriJobManager>>,
    // Note: FriJobManager is not Debug, so we skip it in auto-derive.
    // metrics
    latency_tracker: ComponentStateHandle<GenericComponentState>,
}

impl SnarkJobManager {
    pub fn new(
        // outbound
        prove_batches_sender: Sender<ProofCommand>,
        // config
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
            latency_tracker,
        }
    }

    /// Set the FriJobManager reference for ZiSK data access.
    pub fn set_fri_job_manager(&mut self, fjm: Arc<FriJobManager>) {
        self.fri_job_manager = Some(fjm);
    }

    /// Adds a pending job to the queue.
    /// Awaits if queue is full (ProverJobMap.max_assigned_batch_range).
    pub async fn add_job(&self, batch_envelope: SignedBatchEnvelope<FriProof>) {
        self.jobs.add_job(batch_envelope).await
    }

    // If there is a job pending, returns a non-empty list of tuples (`batch_number`, `verification_key_hash`, `real_fri_proof`)
    pub async fn pick_real_job(
        &self,
        prover_id: String,
    ) -> anyhow::Result<Option<Vec<(FriJob, FriProof)>>> {
        // consume/remove all fake jobs that may be in the front of the queue
        self.process_pending_fake_fri_proofs().await?;

        let batches_with_real_proofs = self
            .jobs
            .pick_jobs_while_with_limit(self.max_fris_per_snark, &prover_id, |job| {
                !job.batch_envelope.data.is_fake()
            })
            .await;

        if batches_with_real_proofs.is_empty() {
            tracing::trace!(prover_id, "no SNARK prove jobs are available for pick up",);
            return Ok(None);
        }

        Ok(Some(batches_with_real_proofs))
    }

    pub async fn submit_proof(
        &self,
        batch_from: u64,
        batch_to: u64,
        proving_version: ProvingVersion,
        payload: Vec<u8>,
        prover_id: String,
    ) -> anyhow::Result<()> {
        // note: we still hold mutex while verifying the proof -
        // this is desired since we don't want the batches to timeout

        // todo: verify_snark_proof()
        // if false {
        //     anyhow::bail!("proof validation failed")
        // }

        // prove is valid - consuming proven batches
        let Some(consumed_batches_proven) = self
            .jobs
            .complete_many_jobs(batch_from, batch_to, ProverType::Real, &prover_id)
            .await
        else {
            anyhow::bail!("race condition: some batches were completed earlier")
        };

        // Prover should generate the proof with VK received from server. These must always match.
        // If they don't, proof won't be accepted, validation will fail, therefore it's pointless to proceed.
        //
        // This should never happen, but we double-check to guarantee it's the case.
        let server_vk = consumed_batches_proven[0]
            .batch
            .verification_key_hash()
            .expect("verification key hash must be present as it was set by server");
        let prover_vk = proving_version.vk_hash();
        anyhow::ensure!(
            server_vk == prover_vk,
            "Verification key hash mismatch: server got {server_vk}, prover got {prover_vk}"
        );

        let consumed_batches_proven: Vec<_> = consumed_batches_proven
            .into_iter()
            .map(|batch| batch.with_stage(BatchExecutionStage::SnarkProvedReal))
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

    /// Submit a two-proof-system proof (Era SNARK + ZiSK SNARK).
    /// Combines both proofs into a single TwoProofSystem variant for L1 submission.
    pub async fn submit_two_proof_system(
        &self,
        batch_from: u64,
        batch_to: u64,
        proving_version: ProvingVersion,
        era_proof: Vec<u8>,
        zisk_proof: Vec<u8>,
        zisk_public_values: Vec<u8>,
        prover_id: String,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            zisk_proof.len() == 768,
            "ZiSK proof must be exactly 768 bytes (24 * 32), got {}",
            zisk_proof.len()
        );
        anyhow::ensure!(
            zisk_public_values.len() == 256,
            "ZiSK public values must be exactly 256 bytes (8 * 32), got {}",
            zisk_public_values.len()
        );
        anyhow::ensure!(
            era_proof.len() % 32 == 0,
            "Era proof must be a multiple of 32 bytes, got {}",
            era_proof.len()
        );

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

        let consumed_batches_proven: Vec<_> = consumed_batches_proven
            .into_iter()
            .map(|batch| batch.with_stage(BatchExecutionStage::SnarkProvedReal))
            .collect();

        self.send_downstream(ProofCommand::new(
            consumed_batches_proven,
            SnarkProof::TwoProofSystem(TwoProofSystemSnarkProof {
                era_proof,
                zisk_proof,
                zisk_public_values,
                proving_execution_version: proving_version as u32,
            }),
        ))
        .await?;
        Ok(())
    }

    /// Consumes fake FRI proofs from the head of the queue and turns them into fake SNARKs.
    async fn process_pending_fake_fri_proofs(&self) -> anyhow::Result<()> {
        self.process_pending_fake_or_timed_out_fri_proofs(None)
            .await
    }

    /// Consumes FRI proofs from the head of the queue that satisfy the following conditions:
    /// * FRI proof is fake
    /// * if `timeout_for_real_fris` is Some, then also jobs that are older than `timeout_for_real_fris`
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

            // Check if ZiSK data is available for two-proof-system.
            // If so, execute ZiSK batch natively to compute commitment and include it.
            let first_batch = completed.first().unwrap().batch_number();
            let zisk_data = if let Some(ref fjm) = self.fri_job_manager {
                fjm.take_zisk_data(first_batch).await
            } else {
                None
            };

            let snark_proof = if let Some(zisk_bincode) = zisk_data {
                let real_snark = std::env::var("ZISK_REAL_PROOFS").is_ok();
                if real_snark {
                    // Generate real ZiSK SNARK proof by running the full pipeline.
                    // This is CPU-intensive (~15 min), so run on a blocking thread.
                    tracing::info!(batch = first_batch, "Starting REAL ZiSK proof generation ({} bytes input)", zisk_bincode.len());
                } else {
                    tracing::info!(batch = first_batch, "Computing ZiSK batch commitment (set ZISK_REAL_PROOFS=1 for real SNARK)");
                }
                let batch_num = first_batch;
                let result = if real_snark {
                    tokio::task::spawn_blocking(move || {
                        generate_zisk_snark_proof(&zisk_bincode, batch_num)
                    }).await.map_err(|e| format!("spawn_blocking: {e}"))
                } else {
                    // Native commitment computation only — timeout after 120s
                    let handle = tokio::task::spawn_blocking(move || {
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            zksync_os_zisk_lib::executor::execute_and_commit_from_bincode(&zisk_bincode)
                        })) {
                            Ok(Ok((_output, commitment))) => {
                                let hash_bytes: [u8; 32] = commitment.into();
                                let mut pv = vec![0u8; 256];
                                pv[..32].copy_from_slice(&hash_bytes);
                                Ok((vec![0u8; 768], pv))
                            }
                            Ok(Err(e)) => Err(e),
                            Err(panic_info) => {
                                let msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                                    s.clone()
                                } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                                    s.to_string()
                                } else {
                                    "unknown panic".to_string()
                                };
                                Err(format!("ZiSK execution panicked: {msg}"))
                            }
                        }
                    });
                    match tokio::time::timeout(Duration::from_secs(120), handle).await {
                        Ok(join_result) => join_result.map_err(|e| format!("spawn_blocking: {e}")),
                        Err(_) => Err("ZiSK commitment computation timed out (120s)".to_string()),
                    }
                };
                match result.and_then(|r| r) {
                    Ok((snark_proof_bytes, public_values)) => {
                        let is_real = snark_proof_bytes.iter().any(|&b| b != 0);
                        tracing::info!(
                            batch = first_batch,
                            real_snark = is_real,
                            commitment = %alloy::primitives::B256::from_slice(&public_values[..32]),
                            "ZiSK proof ready"
                        );
                        if is_real {
                            SnarkProof::TwoProofSystem(TwoProofSystemSnarkProof {
                                era_proof: vec![0u8; 32],
                            zisk_proof: snark_proof_bytes,
                            zisk_public_values: public_values,
                            proving_execution_version: completed
                                .first()
                                .unwrap()
                                .batch
                                .execution_version,
                        })
                        } else {
                            // Commitment computed but no real SNARK — use fake proof for L1
                            SnarkProof::Fake
                        }
                    }
                    Err(e) => {
                        tracing::warn!(batch = first_batch, "ZiSK proof generation failed: {e}");
                        SnarkProof::Fake
                    }
                }
            } else {
                SnarkProof::Fake
            };

            let batches_with_fake_proofs = completed
                .into_iter()
                .map(|batch| batch.with_stage(BatchExecutionStage::SnarkProvedFake))
                .collect();

            self.send_downstream(ProofCommand::new(
                batches_with_fake_proofs,
                snark_proof,
            ))
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

    // config
    max_batch_age: Duration,
    polling_interval: Duration,
}

/// Generate a real ZiSK SNARK proof by running the full pipeline.
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

    // Create temp directory for this batch
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

    // Run STARK aggregation
    let stark_dir = format!("{work_dir}/stark");
    let _ = std::fs::create_dir_all(format!("{stark_dir}/proofs"));
    tracing::info!(batch_number, "Running STARK aggregation...");
    let stark_output = Command::new(format!("{zisk_bin}/cargo-zisk"))
        .args([
            "prove", "-e", &elf_path, "-i", &input_path, "-k", &proving_key,
            "-o", &stark_dir, "--emulator", "--aggregation", "--save-proofs", "-v",
        ])
        .output()
        .map_err(|e| format!("cargo-zisk prove: {e}"))?;
    if !stark_output.status.success() {
        let stderr = String::from_utf8_lossy(&stark_output.stderr);
        return Err(format!("STARK aggregation failed: {}", &stderr[stderr.len().saturating_sub(500)..]));
    }
    let vadcop_path = format!("{stark_dir}/vadcop_final_proof.bin");
    if !std::path::Path::new(&vadcop_path).exists() {
        return Err("vadcop_final_proof.bin not generated".into());
    }
    tracing::info!(batch_number, "STARK aggregation done");

    // Run SNARK wrapping
    let snark_dir = format!("{work_dir}/snark");
    let _ = std::fs::create_dir_all(&snark_dir);
    tracing::info!(batch_number, "Running SNARK wrapping...");
    let snark_output = Command::new(format!("{zisk_bin}/cargo-zisk"))
        .args([
            "prove-snark", "--proof", &vadcop_path, "--elf", &elf_path,
            "--proving-key-snark", &snark_key, "-o", &snark_dir, "-v",
        ])
        .output()
        .map_err(|e| format!("cargo-zisk prove-snark: {e}"))?;
    if !snark_output.status.success() {
        let stderr = String::from_utf8_lossy(&snark_output.stderr);
        return Err(format!("SNARK wrapping failed: {}", &stderr[stderr.len().saturating_sub(500)..]));
    }
    let snark_proof_path = format!("{snark_dir}/final_snark_proof.bin");
    if !std::path::Path::new(&snark_proof_path).exists() {
        return Err("final_snark_proof.bin not generated".into());
    }
    tracing::info!(batch_number, "SNARK wrapping done");

    // Read and parse SNARK proof
    let data = std::fs::read(&snark_proof_path).map_err(|e| format!("read SNARK: {e}"))?;
    let proof_len = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    if proof_len != 768 {
        return Err(format!("unexpected proof length: {proof_len}, expected 768"));
    }
    let snark_proof_bytes = data[8..8 + 768].to_vec();
    let pv_offset = 8 + 768;
    let pv_len = u64::from_le_bytes(data[pv_offset..pv_offset + 8].try_into().unwrap()) as usize;
    if pv_len != 256 {
        return Err(format!("unexpected public values length: {pv_len}, expected 256"));
    }
    let public_values = data[pv_offset + 8..pv_offset + 8 + 256].to_vec();

    // Keep work directory for debugging
    tracing::info!(batch_number, work_dir, "ZiSK proof files preserved for debugging");

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
