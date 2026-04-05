//! Airbender GPU prover process lifecycle management.
//!
//! Starts the Airbender prover with `--iterations N`, waits for it to exit
//! (freeing GPU memory), then lets the `MultiProofCombiner` use the GPU for
//! ZiSK before restarting.

use crate::prover_api::gpu_coordinator::GpuCoordinator;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the Airbender GPU prover subprocess.
pub struct AirbenderGpuConfig {
    pub prover_binary: Option<String>,
    pub crs_file: Option<String>,
    pub app_bin_path: Option<String>,
    pub output_dir: Option<String>,
    pub process_timeout_secs: u64,
    pub iterations_per_round: u32,
}

/// Delay between prover restart attempts on failure.
const PROVER_RETRY_DELAY_SECS: u64 = 10;
/// Brief pause after prover exits to let ZiSK claim GPU.
const GPU_HANDOFF_DELAY_SECS: u64 = 2;

/// Background task that manages the Airbender prover process lifecycle.
pub struct GpuProverOrchestrator {
    config: AirbenderGpuConfig,
    sequencer_url: String,
    max_fris_per_snark: usize,
    coordinator: Arc<GpuCoordinator>,
}

impl GpuProverOrchestrator {
    pub fn new(
        config: AirbenderGpuConfig,
        sequencer_url: String,
        max_fris_per_snark: usize,
        coordinator: Arc<GpuCoordinator>,
    ) -> Self {
        Self {
            config,
            sequencer_url,
            max_fris_per_snark,
            coordinator,
        }
    }

    pub async fn run(self) {
        loop {
            self.coordinator.wait_for_zisk_done().await;

            tracing::info!(
                iterations = self.config.iterations_per_round,
                "Starting Airbender GPU prover"
            );
            self.coordinator.prover_started().await;

            let result = self.run_prover_process().await;

            self.coordinator.prover_stopped().await;

            match result {
                Ok(0) => {
                    tracing::info!("Airbender GPU prover round completed");
                }
                Ok(code) => {
                    tracing::warn!(
                        exit_code = code,
                        retry_delay_secs = PROVER_RETRY_DELAY_SECS,
                        "Airbender GPU prover exited with error"
                    );
                    tokio::time::sleep(Duration::from_secs(PROVER_RETRY_DELAY_SECS)).await;
                }
                Err(e) => {
                    tracing::error!(
                        retry_delay_secs = PROVER_RETRY_DELAY_SECS,
                        "Airbender GPU prover failed: {e:#}"
                    );
                    tokio::time::sleep(Duration::from_secs(PROVER_RETRY_DELAY_SECS)).await;
                }
            }

            tokio::time::sleep(Duration::from_secs(GPU_HANDOFF_DELAY_SECS)).await;
        }
    }

    async fn run_prover_process(&self) -> anyhow::Result<i32> {
        let binary = self
            .config
            .prover_binary
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("gpu_prover_binary not configured"))?;
        let crs_file = self
            .config
            .crs_file
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("gpu_prover_crs_file not configured"))?;
        let app_bin = self
            .config
            .app_bin_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("gpu_prover_app_bin not configured"))?;
        const DEFAULT_PROVER_OUTPUT_DIR: &str = "./db/prover_output";
        let output_dir = self
            .config
            .output_dir
            .as_deref()
            .unwrap_or(DEFAULT_PROVER_OUTPUT_DIR);

        let _ = std::fs::create_dir_all(output_dir);

        let mut child = tokio::process::Command::new(binary)
            .arg("--sequencer-urls")
            .arg(&self.sequencer_url)
            .arg("--output-dir")
            .arg(output_dir)
            .arg("--trusted-setup-file")
            .arg(crs_file)
            .arg("--app-bin-path")
            .arg(app_bin)
            .arg("--max-fris-per-snark")
            .arg(self.max_fris_per_snark.to_string())
            .arg("--iterations")
            .arg(self.config.iterations_per_round.to_string())
            .env("RUST_MIN_STACK", "536870912")
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn {binary}: {e}"))?;

        let timeout = Duration::from_secs(self.config.process_timeout_secs);
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => Ok(status.code().unwrap_or(1)),
            Ok(Err(e)) => {
                tracing::error!("Airbender prover wait error: {e}");
                Err(e.into())
            }
            Err(_) => {
                tracing::error!(
                    timeout_secs = self.config.process_timeout_secs,
                    "Airbender prover timeout, killing process"
                );
                let _ = child.kill().await;
                Err(anyhow::anyhow!("prover process timed out after {timeout:?}"))
            }
        }
    }
}
