use crate::batcher_metrics::BatchExecutionStage;
use crate::batcher_model::{FriProof, SignedBatchEnvelope, SnarkProof};
use crate::commands::SendToL1;
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::sol_types::SolCall;
use std::collections::HashMap;
use std::fmt::Display;
use zksync_os_contract_interface::IExecutor;
use zksync_os_contract_interface::IExecutor::{proofPayloadCall, proveBatchesSharedBridgeCall};
use zksync_os_contract_interface::models::StoredBatchInfo;

const OHBENDER_PROOF_TYPE: u32 = 2;
const FAKE_PROOF_TYPE: u32 = 3;
const FAKE_PROOF_MAGIC_VALUE: u32 = 13;
const MULTI_PROOF_TYPE: u32 = 5;

#[derive(Debug)]
pub struct ProofCommand {
    batches: Vec<SignedBatchEnvelope<FriProof>>,
    proof: SnarkProof,
}

impl ProofCommand {
    pub fn new(batches: Vec<SignedBatchEnvelope<FriProof>>, proof: SnarkProof) -> Self {
        Self { batches, proof }
    }
}

impl SendToL1 for ProofCommand {
    const NAME: &'static str = "prove";
    const SENT_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1TxSent;
    const MINED_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1TxMined;
    const PASSTHROUGH_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1Passthrough;

    fn solidity_call(&self, _gateway: bool, _operator: &Address) -> Bytes {
        proveBatchesSharedBridgeCall::new((
            self.batches.first().unwrap().batch.batch_info.chain_address,
            U256::from(self.batches.first().unwrap().batch_number()),
            U256::from(self.batches.last().unwrap().batch_number()),
            self.to_calldata_suffix().into(),
        ))
        .abi_encode()
        .into()
    }
}

impl AsRef<[SignedBatchEnvelope<FriProof>]> for ProofCommand {
    fn as_ref(&self) -> &[SignedBatchEnvelope<FriProof>] {
        self.batches.as_slice()
    }
}

impl AsMut<[SignedBatchEnvelope<FriProof>]> for ProofCommand {
    fn as_mut(&mut self) -> &mut [SignedBatchEnvelope<FriProof>] {
        self.batches.as_mut_slice()
    }
}

impl From<ProofCommand> for Vec<SignedBatchEnvelope<FriProof>> {
    fn from(value: ProofCommand) -> Self {
        value.batches
    }
}

impl Display for ProofCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prove batches {}-{}",
            self.batches.first().unwrap().batch_number(),
            self.batches.last().unwrap().batch_number()
        )?;
        Ok(())
    }
}

impl ProofCommand {
    fn shift_b256_right(input: &B256) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[4..32].copy_from_slice(&input.as_slice()[0..28]);
        B256::from_slice(&bytes)
    }

    fn get_batch_public_input(prev_batch: &StoredBatchInfo, batch: &StoredBatchInfo) -> B256 {
        let mut bytes = Vec::with_capacity(32 * 3);
        bytes.extend_from_slice(prev_batch.state_commitment.as_slice());
        bytes.extend_from_slice(batch.state_commitment.as_slice());
        bytes.extend_from_slice(batch.commitment.as_slice());
        keccak256(&bytes)
    }
    fn snark_public_input(previous_batch: &StoredBatchInfo, batches: &[StoredBatchInfo]) -> B256 {
        let mut hash_map: HashMap<usize, &StoredBatchInfo> = HashMap::new();
        hash_map.insert(previous_batch.batch_number as usize, previous_batch);
        for batch in batches {
            hash_map.insert(batch.batch_number as usize, batch);
        }
        let start = batches.first().unwrap().batch_number as usize;
        let end = batches.last().unwrap().batch_number as usize;

        // taken from https://github.com/mm-zk/zksync_tools/blob/cf2c47d61fa8399a030d0b31d4396832f802489b/prove_execute/src/main.rs
        let mut result: Option<B256> = None;
        for i in start..=end {
            let batch = hash_map.get(&i).expect("Batch not found");
            let prev_batch = hash_map.get(&(i - 1)).expect("Previous batch not found");
            let public_input = Self::get_batch_public_input(prev_batch, batch);
            // Snark public input is public_input >> 32.
            let snark_input = Self::shift_b256_right(&public_input);

            match result {
                Some(ref mut res) => {
                    // Combine with previous result.
                    let mut combined = [0_u8; 64];
                    combined[..32].copy_from_slice(&res.0);
                    combined[32..].copy_from_slice(&snark_input.0);
                    *res = Self::shift_b256_right(&keccak256(combined));
                }
                None => {
                    result = Some(snark_input);
                }
            }
        }
        result.unwrap()
    }
    fn to_calldata_suffix(&self) -> Vec<u8> {
        let previous_batch_info = &self
            .batches
            .first()
            .unwrap()
            .batch
            .previous_stored_batch_info;
        let stored_batch_infos: Vec<StoredBatchInfo> = self
            .batches
            .iter()
            .map(|batch| {
                batch
                    .batch
                    .batch_info
                    .clone()
                    .into_stored(&batch.batch.protocol_version)
            })
            .collect();
        // todo: awful and temporary
        let verifier_version = match self.proof.proving_execution_version() {
            // Use default verifier for fake proofs.
            None => 0,
            Some(4) => 4,
            Some(5) => 5,
            Some(6) => 6,
            // For multi-proof system, the verifier version is carried alongside.
            // MULTI_PROOF_TYPE (5) tells the MultiProofVerifier to verify both proofs.
            Some(v) if matches!(self.proof, SnarkProof::MultiProof(_)) => v,
            Some(execution_version) => panic!(
                "unsupported or old execution version: {execution_version}; there's no verifier defined for it"
            ),
        };

        // todo: remove tostring
        let public_input = Self::snark_public_input(previous_batch_info, &stored_batch_infos);

        tracing::info!(">> public input: {}", public_input);

        let proof: Vec<U256> = match &self.proof {
            SnarkProof::Fake => {
                vec![
                    // Fake proof type
                    U256::from(FAKE_PROOF_TYPE),
                    // OhBender 'previous hash' - for fake proof, we can always assume that it matches the range perfectly.
                    U256::from(0),
                    // Fake proof magic value (just for sanity)
                    U256::from(FAKE_PROOF_MAGIC_VALUE),
                    // Public input (fake proof **will** verify this against batch data stored in the contract)
                    U256::from_be_bytes(public_input.0),
                ]
            }
            SnarkProof::Real(real) => {
                let proof: Vec<U256> = real
                    .proof()
                    .chunks(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk
                            .try_into()
                            .expect("proof bytes must be a multiple of 32");
                        U256::from_be_bytes(arr)
                    })
                    .collect();
                vec![
                    // Real proof versioned with a specific verifier
                    U256::from(OHBENDER_PROOF_TYPE | (verifier_version << 8)),
                    // we generate SNARK proofs to always match the range perfectly.
                    U256::from(0),
                ]
                .into_iter()
                .chain(proof)
                .collect()
            }
            SnarkProof::MultiProof(multi_proof) => {
                // Validate proof sizes (invariants from MultiProofSnarkProof construction).
                assert_eq!(
                    multi_proof.zisk_proof.len(), 768,
                    "ZiSK proof must be exactly 768 bytes, got {}",
                    multi_proof.zisk_proof.len()
                );
                assert_eq!(
                    multi_proof.zisk_public_values.len(), 256,
                    "ZiSK public values must be exactly 256 bytes, got {}",
                    multi_proof.zisk_public_values.len()
                );
                assert!(
                    multi_proof.era_proof.len() % 32 == 0,
                    "Era proof must be a multiple of 32 bytes, got {}",
                    multi_proof.era_proof.len()
                );

                // Cross-proof validation: both proof systems must commit to the same batch.
                let zisk_commitment =
                    B256::from_slice(&multi_proof.zisk_public_values[..32]);
                let first_batch_input = Self::get_batch_public_input(
                    previous_batch_info,
                    stored_batch_infos
                        .first()
                        .expect("stored_batch_infos must not be empty"),
                );
                assert_eq!(
                    zisk_commitment, first_batch_input,
                    "ZiSK batch commitment {zisk_commitment} does not match \
                     Era batch commitment {first_batch_input}"
                );
                tracing::info!("Cross-proof validation passed: commitments match");

                // Era (Airbender) SNARK proof as U256 chunks
                let era_chunks: Vec<U256> = multi_proof
                    .era_proof
                    .chunks(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk
                            .try_into()
                            .expect("era proof bytes must be a multiple of 32");
                        U256::from_be_bytes(arr)
                    })
                    .collect();

                // ZiSK SNARK proof as U256 chunks (always 24 elements = 768 bytes)
                let zisk_proof_chunks: Vec<U256> = multi_proof
                    .zisk_proof
                    .chunks(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk
                            .try_into()
                            .expect("zisk proof must be 768 bytes (24 * 32)");
                        U256::from_be_bytes(arr)
                    })
                    .collect();

                // ZiSK public values as U256 chunks (always 8 elements = 256 bytes)
                let zisk_pv_chunks: Vec<U256> = multi_proof
                    .zisk_public_values
                    .chunks(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk
                            .try_into()
                            .expect("zisk public values must be 256 bytes (8 * 32)");
                        U256::from_be_bytes(arr)
                    })
                    .collect();

                // Multi-proof encoding (MULTI_PROOF_TYPE = 5).
                // The MultiProofVerifier requires BOTH proofs to pass.
                // Layout:
                // [0] = MULTI_PROOF_TYPE | (verifier_version << 8)
                // [1] = 0 (previous hash)
                // [2] = N (number of Airbender proof elements)
                // [3 .. 3+N] = Airbender SNARK proof elements
                // [3+N .. 3+N+24] = ZiSK SNARK proof (24 uint256s)
                // [3+N+24 .. 3+N+32] = ZiSK public values (8 uint256s)
                let mut proof_vec = vec![
                    U256::from(MULTI_PROOF_TYPE | (verifier_version << 8)),
                    U256::from(0),                    // previous hash
                    U256::from(era_chunks.len()),      // N
                ];
                proof_vec.extend(era_chunks);          // Airbender proof
                proof_vec.extend(zisk_proof_chunks);   // ZiSK SNARK (24)
                proof_vec.extend(zisk_pv_chunks);      // ZiSK public values (8)
                proof_vec
            }
        };

        let proof_payload = proofPayloadCall {
            old: IExecutor::StoredBatchInfo::from(previous_batch_info),
            newInfo: stored_batch_infos
                .iter()
                .map(Into::into) // into `IExecutor::StoredBatchInfo`
                .collect(),
            proof,
        };

        /// Current commitment encoding version as per protocol.
        const SUPPORTED_ENCODING_VERSION: u8 = 1;

        let mut proof_data = vec![SUPPORTED_ENCODING_VERSION];
        proof_payload.abi_encode_raw(&mut proof_data);
        proof_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher_model::MultiProofSnarkProof;

    #[test]
    fn test_multi_proof_serde_roundtrip() {
        let multi_proof = MultiProofSnarkProof {
            era_proof: vec![0xAB; 64],
            zisk_proof: vec![0xCD; 768],
            zisk_public_values: vec![0xEF; 256],
            proving_execution_version: 6,
        };
        let snark = SnarkProof::MultiProof(multi_proof);
        let json = serde_json::to_string(&snark).unwrap();
        let decoded: SnarkProof = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.proving_execution_version(), Some(6));
        assert_eq!(decoded.proof().unwrap().len(), 64);
    }

    #[test]
    fn test_multi_proof_proving_version() {
        let snark = SnarkProof::MultiProof(MultiProofSnarkProof {
            era_proof: vec![],
            zisk_proof: vec![],
            zisk_public_values: vec![],
            proving_execution_version: 6,
        });
        assert_eq!(snark.proving_execution_version(), Some(6));

        // era_proof is returned from proof()
        let snark2 = SnarkProof::MultiProof(MultiProofSnarkProof {
            era_proof: vec![1, 2, 3],
            zisk_proof: vec![4, 5, 6],
            zisk_public_values: vec![7, 8, 9],
            proving_execution_version: 5,
        });
        assert_eq!(snark2.proof(), Some(&[1u8, 2, 3][..]));
        assert_eq!(snark2.proving_execution_version(), Some(5));
    }

    #[test]
    fn test_backward_compat_existing_variants() {
        // Fake proof still works
        let fake = SnarkProof::Fake;
        assert_eq!(fake.proving_execution_version(), None);
        assert!(fake.proof().is_none());

        // Real proof still works
        let real = SnarkProof::Real(crate::batcher_model::RealSnarkProof::V2 {
            proof: vec![0xAA; 32],
            proving_execution_version: 6,
        });
        assert_eq!(real.proving_execution_version(), Some(6));
        assert_eq!(real.proof().unwrap().len(), 32);
    }

    #[test]
    fn test_multi_proof_type_constant() {
        // MULTI_PROOF_TYPE must be distinct from existing types
        assert_ne!(MULTI_PROOF_TYPE, OHBENDER_PROOF_TYPE);
        assert_ne!(MULTI_PROOF_TYPE, FAKE_PROOF_TYPE);
        assert_eq!(MULTI_PROOF_TYPE, 5);
    }

    #[test]
    fn test_multi_proof_encoding_type_field() {
        // Verify the proof type encoding formula
        let verifier_version: u32 = 6;
        let encoded = MULTI_PROOF_TYPE | (verifier_version << 8);
        // Type is in low byte
        assert_eq!(encoded & 0xFF, MULTI_PROOF_TYPE);
        // Version is in higher bytes
        assert_eq!(encoded >> 8, verifier_version);
    }
}
