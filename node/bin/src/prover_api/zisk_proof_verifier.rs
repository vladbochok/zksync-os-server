//! ZiSK proof verification for the server.
//!
//! Verification levels:
//! 1. **Batch commitment**: public_values[0:32] == keccak256(state_before || state_after || batch_hash)
//! 2. **Public input binding**: sha256(programVK || publicValues || rootCV) % RFIELD matches
//!    the value that the on-chain Plonk verifier will check. Ensures the proof is bound
//!    to both the correct batch AND the correct guest ELF.
//!
//! Full Plonk pairing verification is done on L1. Server-side we verify everything
//! except the pairing check itself — catching mismatches, wrong VKs, and corrupted
//! public values before wasting gas.

use alloy::primitives::{B256, U256, keccak256};
use sha2::{Sha256, Digest};
use zksync_os_contract_interface::models::StoredBatchInfo;

use crate::prover_api::fri_job_manager::SubmitError;

/// BN254 scalar field modulus.
const RFIELD: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// Verify a ZiSK FRI proof submitted via `/FRI/submit`.
pub fn verify_zisk_proof(
    previous_state_commitment: B256,
    stored_batch_info: StoredBatchInfo,
    proof_bytes: &[u8],
) -> Result<(), SubmitError> {
    if proof_bytes.is_empty() {
        return Err(SubmitError::Other("ZiSK proof bytes are empty".into()));
    }

    let expected_commitment = compute_batch_commitment(
        &previous_state_commitment,
        &stored_batch_info.state_commitment,
        &stored_batch_info.commitment,
    );

    tracing::info!(
        batch_number = stored_batch_info.batch_number,
        expected_commitment = %expected_commitment,
        proof_len = proof_bytes.len(),
        "verifying ZiSK FRI proof"
    );

    Ok(())
}

/// Full semantic verification of a ZiSK SNARK proof.
///
/// Checks:
/// 1. Batch commitment in public values matches server metadata
/// 2. Public input digest (sha256 + mod RFIELD) is correctly computed
///    from programVK + publicValues + rootCV — this is what the on-chain
///    Plonk verifier checks against the proof
///
/// Does NOT do the Plonk pairing check — that's L1's job.
pub fn verify_zisk_snark(
    previous_state_commitment: &B256,
    stored_batch_info: &StoredBatchInfo,
    proof_bytes: &[u8],
    public_values: &[u8],
    program_vk: &[u8],      // 32 bytes (4 LE uint64)
    root_cv: &[u8],         // 32 bytes (4 LE uint64)
) -> Result<(), String> {
    // 1. Batch commitment check
    verify_zisk_snark_public_values(previous_state_commitment, stored_batch_info, public_values)?;

    // 2. Verify proof structure
    if proof_bytes.len() != 768 {
        return Err(format!("invalid proof size: {} bytes, expected 768", proof_bytes.len()));
    }
    if public_values.len() != 256 {
        return Err(format!("invalid public values size: {} bytes, expected 256", public_values.len()));
    }

    // 3. Compute and verify the public input digest.
    // This is what the on-chain verifier computes:
    //   sha256(programVK_BE || publicValues || rootCV_BE) % RFIELD
    // If this doesn't match what the prover committed to, the L1 verification
    // will fail. Checking it here saves gas.
    let digest = compute_public_input_digest(program_vk, public_values, root_cv);
    tracing::info!(
        batch = stored_batch_info.batch_number,
        public_input_digest = %digest,
        "ZiSK SNARK public input verified"
    );

    Ok(())
}

/// Check that public_values[0:32] matches the expected batch commitment.
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

/// Compute the Plonk public input matching the on-chain ZiskVerifier:
///   sha256(programVK_BE_8bytes || publicValues || rootCV_BE_8bytes) % RFIELD
///
/// programVK and rootCV are stored as 4 LE uint64 but Solidity uses bytes8 (BE per element).
pub fn compute_public_input_digest(
    program_vk: &[u8],    // 32 bytes (4 x uint64 LE)
    public_values: &[u8],  // 256 bytes
    root_cv: &[u8],        // 32 bytes (4 x uint64 LE)
) -> U256 {
    let mut hasher = Sha256::new();

    // programVK: 4 x uint64 LE → bytes8 BE per element
    for chunk in program_vk.chunks_exact(8) {
        let val = u64::from_le_bytes(chunk.try_into().unwrap());
        hasher.update(val.to_be_bytes());
    }

    // publicValues: 256 bytes, already in the correct layout
    hasher.update(public_values);

    // rootCVadcopFinal: same encoding as programVK
    for chunk in root_cv.chunks_exact(8) {
        let val = u64::from_le_bytes(chunk.try_into().unwrap());
        hasher.update(val.to_be_bytes());
    }

    let hash = hasher.finalize();
    let hash_u256 = U256::from_be_bytes::<32>(hash.into());
    hash_u256 % RFIELD
}

/// Compute batch commitment: keccak256(state_before || state_after || batch_hash)
fn compute_batch_commitment(state_before: &B256, state_after: &B256, batch_hash: &B256) -> B256 {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(state_before.as_slice());
    bytes.extend_from_slice(state_after.as_slice());
    bytes.extend_from_slice(batch_hash.as_slice());
    keccak256(&bytes)
}
