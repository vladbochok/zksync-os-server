//! GPU coordination between Airbender prover and ZiSK proof generation.
//!
//! Both the Airbender prover (external process) and ZiSK STARK aggregation need
//! exclusive GPU access. This module provides the shared coordination state.
//!
//! Used by:
//! - `GpuProverOrchestrator` — signals prover start/stop
//! - `MultiProofCombiner` — acquires/releases GPU for ZiSK

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// Shared GPU coordination state.
///
/// State machine:
/// ```text
/// [Airbender running] → prover_stopped() → [GPU free]
///     → acquire_gpu_for_zisk() → [ZiSK running]
///     → release_gpu_from_zisk() → [GPU free]
///     → wait_for_zisk_done() → [Airbender starts]
/// ```
pub struct GpuCoordinator {
    /// True when the Airbender prover process is active.
    prover_running: Mutex<bool>,
    /// Signaled when the prover exits (GPU becomes available).
    gpu_available: Notify,
    /// Signaled when ZiSK finishes (GPU available for Airbender restart).
    zisk_done: Notify,
    /// True when ZiSK is generating proofs on GPU.
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

    /// Mark the Airbender prover as running (GPU occupied).
    pub async fn prover_started(&self) {
        *self.prover_running.lock().await = true;
    }

    /// Mark the Airbender prover as stopped (GPU available).
    pub async fn prover_stopped(&self) {
        *self.prover_running.lock().await = false;
        self.gpu_available.notify_waiters();
    }

    /// Wait for the Airbender prover to exit, then claim GPU for ZiSK.
    /// Logs a warning every 60s while waiting.
    pub async fn acquire_gpu_for_zisk(&self) {
        loop {
            if !*self.prover_running.lock().await {
                *self.zisk_pending.lock().await = true;
                return;
            }
            match tokio::time::timeout(Duration::from_secs(60), self.gpu_available.notified()).await
            {
                Ok(()) => {}
                Err(_) => {
                    tracing::warn!("still waiting for GPU (Airbender prover running)");
                }
            }
        }
    }

    /// Release GPU after ZiSK finishes.
    pub async fn release_gpu_from_zisk(&self) {
        *self.zisk_pending.lock().await = false;
        self.zisk_done.notify_waiters();
    }

    /// Wait for ZiSK to finish before restarting the Airbender prover.
    pub async fn wait_for_zisk_done(&self) {
        loop {
            if !*self.zisk_pending.lock().await {
                return;
            }
            self.zisk_done.notified().await;
        }
    }
}
