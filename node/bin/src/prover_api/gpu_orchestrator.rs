//! GPU Prover Orchestrator
//!
//! Manages GPU sharing between the Airbender prover (external process) and
//! ZiSK SNARK generation (in-process). Both need the GPU but can't run
//! simultaneously on a single GPU.
//!
//! Flow per round:
//! 1. Start Airbender prover with `--iterations N` (exits after N SNARKs)
//! 2. Wait for it to exit (GPU freed)
//! 3. MultiProofCombiner acquires GPU lock, runs ZiSK STARK+SNARK
//! 4. ZiSK finishes, releases GPU lock
//! 5. Restart Airbender prover

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// Shared GPU coordination state.
pub struct GpuCoordinator {
    prover_running: Mutex<bool>,
    gpu_available: Notify,
    zisk_done: Notify,
    zisk_pending: Mutex<bool>,
}

impl GpuCoordinator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            prover_running: Mutex::new(false),
            gpu_available: Notify::new(),
            zisk_done: Notify::new(),
            zisk_pending: Mutex::new(false),
        })
    }

    pub async fn prover_started(&self) {
        *self.prover_running.lock().await = true;
    }

    pub async fn prover_stopped(&self) {
        *self.prover_running.lock().await = false;
        self.gpu_available.notify_waiters();
    }

    pub async fn acquire_gpu_for_zisk(&self) {
        loop {
            if !*self.prover_running.lock().await {
                *self.zisk_pending.lock().await = true;
                return;
            }
            self.gpu_available.notified().await;
        }
    }

    pub async fn release_gpu_from_zisk(&self) {
        *self.zisk_pending.lock().await = false;
        self.zisk_done.notify_waiters();
    }

    pub async fn wait_for_zisk_done(&self) {
        loop {
            if !*self.zisk_pending.lock().await {
                return;
            }
            self.zisk_done.notified().await;
        }
    }
}

/// Configuration for the Airbender GPU prover subprocess.
pub struct AirbenderGpuConfig {
    pub prover_binary: Option<String>,
    pub crs_file: Option<String>,
    pub app_bin_path: Option<String>,
    pub output_dir: Option<String>,
    pub process_timeout_secs: u64,
    pub iterations_per_round: u32,
}

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
                    tracing::info!("Airbender prover completed successfully");
                }
                Ok(code) => {
                    tracing::warn!(exit_code = code, "Airbender prover exited with error, retrying in 10s");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Err(e) => {
                    tracing::error!("Airbender prover failed: {e:#}, retrying in 10s");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }

            // Brief pause to let ZiSK claim GPU if needed.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn run_prover_process(&self) -> anyhow::Result<i32> {
        let binary = self.config.prover_binary.as_deref()
            .ok_or_else(|| anyhow::anyhow!("airbender_gpu.prover_binary not configured"))?;
        let crs_file = self.config.crs_file.as_deref()
            .ok_or_else(|| anyhow::anyhow!("airbender_gpu.crs_file not configured"))?;
        let app_bin = self.config.app_bin_path.as_deref()
            .ok_or_else(|| anyhow::anyhow!("airbender_gpu.app_bin_path not configured"))?;
        let output_dir = self.config.output_dir.as_deref().unwrap_or("/tmp/prover_output");

        let _ = std::fs::create_dir_all(output_dir);

        // Spawn child process directly (no shell, no injection risk).
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
