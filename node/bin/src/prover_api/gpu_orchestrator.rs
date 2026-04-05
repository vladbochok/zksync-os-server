//! GPU Prover Orchestrator
//!
//! Manages GPU sharing between the Airbender prover (external process) and
//! ZiSK SNARK generation (in-process). Both need the GPU but can't run
//! simultaneously (not enough VRAM).
//!
//! Flow:
//! 1. Start Airbender prover with `--iterations N`
//! 2. Airbender generates FRI + SNARK proofs on GPU, then exits
//! 3. MultiProofCombiner acquires GPU lock, runs ZiSK STARK on GPU
//! 4. ZiSK finishes, releases GPU lock
//! 5. Restart Airbender prover for the next round

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// Shared GPU coordination state.
pub struct GpuCoordinator {
    /// True when the Airbender prover process is running (GPU occupied).
    prover_running: Mutex<bool>,
    /// Notified when the Airbender prover exits (GPU available for ZiSK).
    gpu_available: Notify,
    /// Notified when ZiSK finishes (GPU available for Airbender restart).
    zisk_done: Notify,
    /// True when there are pending ZiSK proofs waiting for GPU.
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

    /// Called by the orchestrator when the Airbender prover starts.
    pub async fn prover_started(&self) {
        *self.prover_running.lock().await = true;
    }

    /// Called by the orchestrator when the Airbender prover exits.
    pub async fn prover_stopped(&self) {
        *self.prover_running.lock().await = false;
        self.gpu_available.notify_waiters();
    }

    /// Called by MultiProofCombiner to wait for GPU availability.
    /// Returns immediately if the prover is not running.
    pub async fn acquire_gpu_for_zisk(&self) {
        loop {
            {
                let running = self.prover_running.lock().await;
                if !*running {
                    *self.zisk_pending.lock().await = true;
                    return;
                }
            }
            self.gpu_available.notified().await;
        }
    }

    /// Called by MultiProofCombiner when ZiSK finishes using GPU.
    pub async fn release_gpu_from_zisk(&self) {
        *self.zisk_pending.lock().await = false;
        self.zisk_done.notify_waiters();
    }

    /// Called by the orchestrator to wait for ZiSK to finish before restarting the prover.
    pub async fn wait_for_zisk_done(&self) {
        loop {
            {
                let pending = self.zisk_pending.lock().await;
                if !*pending {
                    return;
                }
            }
            self.zisk_done.notified().await;
        }
    }

    /// Check if there are pending ZiSK proofs.
    pub async fn has_pending_zisk(&self) -> bool {
        *self.zisk_pending.lock().await
    }
}

/// Configuration for the Airbender prover process.
pub struct AirbenderProverConfig {
    pub prover_binary: String,
    pub sequencer_url: String,
    pub output_dir: String,
    pub trusted_setup_file: String,
    pub app_bin_path: String,
    pub max_fris_per_snark: u32,
    /// Number of SNARK proofs to generate before exiting (to free GPU for ZiSK).
    pub iterations_per_round: u32,
}

/// Background task that manages the Airbender prover process lifecycle.
pub struct GpuProverOrchestrator {
    config: AirbenderProverConfig,
    coordinator: Arc<GpuCoordinator>,
}

impl GpuProverOrchestrator {
    pub fn new(config: AirbenderProverConfig, coordinator: Arc<GpuCoordinator>) -> Self {
        Self { config, coordinator }
    }

    pub async fn run(self) {
        loop {
            // Wait for any pending ZiSK work to finish before starting the prover.
            self.coordinator.wait_for_zisk_done().await;

            tracing::info!("Starting Airbender GPU prover (iterations={})", self.config.iterations_per_round);
            self.coordinator.prover_started().await;

            let result = self.run_prover_process().await;

            self.coordinator.prover_stopped().await;

            match result {
                Ok(exit_code) => {
                    tracing::info!("Airbender prover exited (code={exit_code})");
                    if exit_code != 0 {
                        tracing::warn!("Airbender prover failed, retrying in 10s");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to run Airbender prover: {e:#}");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }

            // Brief pause before next round to let ZiSK claim GPU if needed.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn run_prover_process(&self) -> anyhow::Result<i32> {
        use tokio::process::Command;

        let mut cmd = Command::new("bash");
        cmd.args([
            "-c",
            &format!(
                "ulimit -s unlimited; exec env RUST_MIN_STACK=536870912 {} \
                 --sequencer-urls {} \
                 --output-dir {} \
                 --trusted-setup-file {} \
                 --app-bin-path {} \
                 --max-fris-per-snark {} \
                 --iterations {}",
                self.config.prover_binary,
                self.config.sequencer_url,
                self.config.output_dir,
                self.config.trusted_setup_file,
                self.config.app_bin_path,
                self.config.max_fris_per_snark,
                self.config.iterations_per_round,
            ),
        ]);

        let status = cmd.status().await?;
        Ok(status.code().unwrap_or(-1))
    }
}
