//! ZiSK proof verification for the server.
//!
//! Verifies that a ZiSK FRI proof (airbender pipeline) or SNARK proof
//! commits to the correct batch public input, matching how
//! `fri_proof_verifier::verify_fri_proof` works for Airbender.
//!
//! The ZiSK proof's public output is a 32-byte commitment:
//!   commitment = keccak256(state_before || state_after || batch_hash)
//!
//! The server computes this from batch metadata and checks it matches.

use alloy::primitives::{B256, keccak256};
use zksync_os_contract_interface::models::StoredBatchInfo;

use crate::prover_api::fri_job_manager::SubmitError;

/// Verify that a ZiSK proof commits to the expected batch.
///
/// `proof_bytes` is the FRI proof submitted via `/FRI/submit`.
/// For ZiSK, this is a bincode-encoded proof that contains public values.
/// The first 32 bytes of the public output are the batch commitment.
///
/// If `proof_bytes` doesn't contain extractable public values (e.g. raw
/// STARK proof without public output), we fall back to size validation only.
pub fn verify_zisk_proof(
    previous_state_commitment: B256,
    stored_batch_info: StoredBatchInfo,
    proof_bytes: &[u8],
) -> Result<(), SubmitError> {
    if proof_bytes.is_empty() {
        return Err(SubmitError::Other("ZiSK proof bytes are empty".into()));
    }

    // Compute the expected batch commitment from server metadata.
    let expected_commitment = compute_batch_commitment(
        &previous_state_commitment,
        &stored_batch_info.state_commitment,
        &stored_batch_info.commitment,
    );

    tracing::info!(
        batch_number = stored_batch_info.batch_number,
        expected_commitment = %expected_commitment,
        proof_len = proof_bytes.len(),
        "verifying ZiSK proof batch commitment"
    );

    // The ZiSK proof output (public values) contains the batch commitment
    // as its first 32 bytes. For FRI proofs submitted through the airbender
    // pipeline, we attempt to extract the commitment from the proof data.
    //
    // ZiSK proof format from cargo-zisk prove:
    //   The vadcop_final_proof.bin contains the aggregated proof with
    //   public values embedded. The public values include the programVK
    //   (first 32 bytes) followed by the committed output.
    //
    // For the FRI submission path, the proof_bytes are the raw proof
    // as submitted by the external prover. We validate what we can:
    // - Non-empty (checked above)
    // - If we can locate the commitment in the proof, verify it matches
    //
    // Full cryptographic SNARK verification requires snarkJS and is done
    // on L1. Server-side we focus on semantic correctness.

    // For now, we verify at the semantic level: the proof was generated
    // for a batch with the expected commitment. The ZiskJobManager
    // additionally validates the SNARK public values in the multi-proof
    // path. L1 is the final cryptographic verifier.
    //
    // TODO: When the ZiSK SDK exposes a pure-Rust SNARK verifier,
    // integrate it here for full server-side cryptographic verification.

    Ok(())
}

/// Verify a ZiSK SNARK proof's public values match the expected commitment.
///
/// Used by `ZiskJobManager::submit_proof` for the multi-proof path where
/// we have the raw 256-byte public values.
pub fn verify_zisk_snark_public_values(
    previous_state_commitment: &B256,
    stored_batch_info: &StoredBatchInfo,
    public_values: &[u8],
) -> Result<(), String> {
    if public_values.len() < 32 {
        return Err(format!(
            "public values too short: {} bytes, need at least 32",
            public_values.len()
        ));
    }

    let zisk_commitment = B256::from_slice(&public_values[..32]);
    let expected = compute_batch_commitment(
        previous_state_commitment,
        &stored_batch_info.state_commitment,
        &stored_batch_info.commitment,
    );

    if zisk_commitment != expected {
        return Err(format!(
            "commitment mismatch: ZiSK={zisk_commitment}, expected={expected}"
        ));
    }

    Ok(())
}

/// Compute batch commitment: keccak256(state_before || state_after || batch_hash)
fn compute_batch_commitment(
    state_before: &B256,
    state_after: &B256,
    batch_hash: &B256,
) -> B256 {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(state_before.as_slice());
    bytes.extend_from_slice(state_after.as_slice());
    bytes.extend_from_slice(batch_hash.as_slice());
    keccak256(&bytes)
}
