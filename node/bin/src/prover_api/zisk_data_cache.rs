//! Cache for ZiSK batch data awaiting multi-proof composition.
//!
//! Stores serialized ZiSK prover input (`bincode`) per batch, populated by the
//! prover input generator when `second_proof_system` is enabled. Consumed by the
//! `MultiProofCombiner` after the Airbender SNARK is submitted.
//!
//! Separated from `FriJobManager` because FRI is an Airbender concern — the ZiSK
//! data lifecycle is independent of FRI job assignment and timeout management.

use std::collections::HashMap;
use tokio::sync::Mutex;

/// Thread-safe cache for ZiSK batch data.
///
/// Data flows:
/// - **In**: `FriProvingPipelineStep` stores data via [`insert`] when a batch enters FRI proving.
/// - **Out**: `MultiProofCombiner` reads via [`get`] and removes via [`remove`] after successful
///   ZiSK SNARK generation.
pub struct ZiskDataCache {
    inner: Mutex<HashMap<u64, Vec<u8>>>,
}

impl ZiskDataCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Store ZiSK data for a batch. Called when the batch enters the FRI proving pipeline.
    pub async fn insert(&self, batch_number: u64, data: Vec<u8>) {
        self.inner.lock().await.insert(batch_number, data);
    }

    /// Check whether ZiSK data exists for a batch (non-destructive).
    /// Used by `submit_proof` to decide whether to cache the Airbender SNARK.
    pub async fn contains(&self, batch_number: u64) -> bool {
        self.inner.lock().await.contains_key(&batch_number)
    }

    /// Clone ZiSK data for a batch (non-destructive).
    /// Used by `MultiProofCombiner` so the data survives retry on failure.
    pub async fn get(&self, batch_number: u64) -> Option<Vec<u8>> {
        self.inner.lock().await.get(&batch_number).cloned()
    }

    /// Remove ZiSK data for a batch after successful proof generation.
    pub async fn remove(&self, batch_number: u64) -> Option<Vec<u8>> {
        self.inner.lock().await.remove(&batch_number)
    }
}
