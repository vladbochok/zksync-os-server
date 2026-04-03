use alloy::primitives::Address;
use zksync_os_batch_types::BatchInfo;
use zksync_os_contract_interface::models::{L2Log, StoredBatchInfo};
use zksync_os_interface::types::BlockOutput;
use zksync_os_l1_sender::batcher_metrics::BatchExecutionStage;
use zksync_os_l1_sender::batcher_model::{
    BatchEnvelope, BatchForSigning, BatchMetadata, ProverInput,
};
use zksync_os_storage_api::{ReadStateHistory, ReplayRecord, read_multichain_root};
use zksync_os_types::{ProvingVersion, PubdataMode};

/// Takes a vector of blocks and produces a batch envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_batch<ReadState: ReadStateHistory>(
    blocks: &[(
        BlockOutput,
        ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    prev_batch_info: StoredBatchInfo,
    batch_number: u64,
    chain_id: u64,
    chain_address_sl: Address,
    pubdata_mode: PubdataMode,
    sl_chain_id: u64,
    read_state: &ReadState,
) -> anyhow::Result<BatchForSigning<ProverInput>> {
    let block_number_from = blocks.first().unwrap().1.block_context.block_number;
    let block_number_to = blocks.last().unwrap().1.block_context.block_number;
    let execution_version = blocks.first().unwrap().1.block_context.execution_version;
    let protocol_version = blocks.first().unwrap().1.protocol_version.clone();

    let state_view = read_state.state_view_at(block_number_to)?;
    let multichain_root = read_multichain_root(state_view);
    let batch_info = BatchInfo::new(
        blocks
            .iter()
            .map(|(block_output, replay_record, tree, _)| {
                (
                    block_output,
                    &replay_record.block_context,
                    replay_record.transactions.as_slice(),
                    tree,
                )
            })
            .collect(),
        chain_id,
        chain_address_sl,
        batch_number,
        pubdata_mode,
        sl_chain_id,
        multichain_root,
        &protocol_version,
    );

    let mut logs = Vec::new();
    let mut messages = Vec::new();
    for block in blocks {
        for output in block.0.tx_results.iter().flatten() {
            for l2_to_l1_log in &output.l2_to_l1_logs {
                logs.push(L2Log {
                    l2_shard_id: l2_to_l1_log.log.l2_shard_id,
                    is_service: l2_to_l1_log.log.is_service,
                    tx_number_in_batch: l2_to_l1_log.log.tx_number_in_block,
                    sender: l2_to_l1_log.log.sender,
                    key: l2_to_l1_log.log.key,
                    value: l2_to_l1_log.log.value,
                });
                if let Some(preimage) = l2_to_l1_log.preimage.as_ref() {
                    messages.push(preimage.clone());
                }
            }
        }
    }

    let proving_version =
        ProvingVersion::try_from(blocks.first().unwrap().1.protocol_version.clone())?;
    // execution version should be the same for all the blocks, it is ensured by the seal criteria
    let batch_prover_input = compute_batch_prover_input(
        blocks,
        proving_version,
        pubdata_mode,
        multichain_root,
        sl_chain_id,
        &batch_info,
    )?;

    // Sanity check: all blocks in the batch should have the same protocol version
    for (_, replay_record, _, _) in blocks.iter().skip(1) {
        anyhow::ensure!(
            replay_record.protocol_version == protocol_version,
            "mismatched protocol versions in batch: expected {}, found {}; blocks: {:?}",
            protocol_version,
            replay_record.protocol_version,
            blocks,
        );
    }

    let batch_envelope = BatchEnvelope::new(
        BatchMetadata {
            previous_stored_batch_info: prev_batch_info,
            batch_info,
            first_block_number: block_number_from,
            last_block_number: block_number_to,
            pubdata_mode,
            tx_count: blocks
                .iter()
                .map(|(block_output, _, _, _)| block_output.tx_results.len())
                .sum(),
            execution_version,
            protocol_version,
            computational_native_used: Some(
                blocks
                    .iter()
                    .map(|(block_output, _, _, _)| block_output.computational_native_used)
                    .sum(),
            ),
            logs,
            messages,
            multichain_root,
        },
        batch_prover_input,
    )
    .with_stage(BatchExecutionStage::BatchSealed);

    Ok(batch_envelope)
}

fn compute_batch_prover_input(
    blocks: &[(
        zksync_os_interface::types::BlockOutput,
        zksync_os_storage_api::ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    proving_version: ProvingVersion,
    pubdata_mode: PubdataMode,
    multichain_root: alloy::primitives::B256,
    sl_chain_id: u64,
    batch_info: &BatchInfo,
) -> anyhow::Result<ProverInput> {
    use zk_os_forward_system::run::generate_batch_proof_input;
    use zk_os_forward_system_dev::run::generate_batch_proof_input as generate_batch_proof_input_dev;

    if blocks
        .iter()
        .any(|(_, _, _, pi)| pi.is_fake())
    {
        return Ok(ProverInput::Fake);
    }

    // Generate airbender batch witness (primary proof system)
    let da_scheme_u8 = pubdata_mode.da_commitment_scheme() as u8;
    let block_witnesses: Vec<&[u32]> = blocks
        .iter()
        .map(|(_, _, _, pi)| pi.unwrap_real())
        .collect();
    let block_pubdata: Vec<&[u8]> = blocks
        .iter()
        .map(|(bo, _, _, _)| bo.pubdata.as_slice())
        .collect();

    let witness = match proving_version {
        ProvingVersion::V1 | ProvingVersion::V2 | ProvingVersion::V3
        | ProvingVersion::V4 | ProvingVersion::V5 => {
            panic!("sealing batch with prover version v1-v5 is not supported");
        }
        ProvingVersion::V6 | ProvingVersion::ZiskV1 => {
            let da = da_scheme_u8.try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert DA commitment scheme"))?;
            generate_batch_proof_input(block_witnesses, da, block_pubdata)
        }
        ProvingVersion::V7 => {
            let da = da_scheme_u8.try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert DA commitment scheme"))?;
            generate_batch_proof_input_dev(block_witnesses, da, block_pubdata)
        }
    };

    // If any block carries ZiSK data, assemble the batch-level ZiSK BatchInput
    let has_zisk = blocks.iter().any(|(_, _, _, pi)| pi.zisk_data().is_some());
    let zisk_data = if has_zisk {
        Some(assemble_zisk_batch(blocks, pubdata_mode, multichain_root, sl_chain_id, batch_info)?)
    } else {
        None
    };

    Ok(ProverInput::Real { witness, zisk_data })
}

/// Assemble per-block ZiSK data into a single batch-level BatchInput.
fn assemble_zisk_batch(
    blocks: &[(
        zksync_os_interface::types::BlockOutput,
        zksync_os_storage_api::ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    pubdata_mode: PubdataMode,
    multichain_root: alloy::primitives::B256,
    sl_chain_id: u64,
    batch_info: &BatchInfo,
) -> anyhow::Result<Vec<u8>> {
    use blake2::{Blake2s256, Digest};
    use crate::prover_input_generator::zisk_input_builder::ZiskBlockData;
    use zksync_os_zisk_lib::types::*;

    let mut block_data_vec = Vec::with_capacity(blocks.len());
    for (_, _, _, pi) in blocks {
        let bytes = pi.zisk_data().expect("ZiSK data missing from ProverInput");
        let data: ZiskBlockData = bincode1::deserialize(bytes)
            .expect("failed to deserialize ZiSK BlockData");
        block_data_vec.push(data);
    }

    let first = &block_data_vec[0];
    let first_replay = &blocks.first().unwrap().1;
    let first_ctx = &first_replay.block_context;
    let da_scheme = pubdata_mode.da_commitment_scheme() as u8;

    let pubdata: Vec<u8> = blocks
        .iter()
        .flat_map(|(bo, _, _, _)| bo.pubdata.iter().copied())
        .collect();

    let block_hashes_blake_before = {
        let mut hasher = Blake2s256::new();
        for hash in &first_ctx.block_hashes.0[1..] {
            hasher.update(hash.to_be_bytes::<32>());
        }
        hasher.update(first_ctx.block_hashes.0[0].to_be_bytes::<32>());
        alloy::primitives::B256::from_slice(&hasher.finalize())
    };

    let previous_block_hashes: Vec<alloy::primitives::B256> = first_ctx
        .block_hashes
        .0[1..]
        .iter()
        .map(|h| alloy::primitives::B256::from(h.to_be_bytes::<32>()))
        .collect();

    let upgrade_tx_hash = batch_info
        .upgrade_tx_hash
        .unwrap_or(alloy::primitives::B256::ZERO);

    let spec_id = match crate::prover_input_generator::zisk_input_builder::spec_id_from_execution_version(
        first_ctx.execution_version,
    ) {
        zksync_os_revm::ZkSpecId::AtlasV1 => 0u8,
        zksync_os_revm::ZkSpecId::AtlasV2 => 1u8,
    };

    let batch_input = BatchInput {
        chain_id: first_ctx.chain_id,
        spec_id,
        protocol_version_minor: first_replay.protocol_version.minor as u32,
        batch_meta: BatchMeta {
            tree_root_before: first.tree_root_before,
            leaf_count_before: first.leaf_count_before,
            block_number_before: first.block_number_before,
            last_block_timestamp_before: first.previous_block_timestamp,
            block_hashes_blake_before,
            previous_block_hashes,
            upgrade_tx_hash,
            da_commitment_scheme: da_scheme,
            pubdata,
            multichain_root,
            sl_chain_id,
            blob_versioned_hashes: vec![],
            // Single-block batch: use block's tree update directly.
            // Multi-block: would need chaining (leaves None, guest rejects
            // if REVM produces storage writes).
            tree_update: if block_data_vec.len() == 1 {
                block_data_vec[0].tree_update.clone()
            } else {
                // Multi-block: would need chaining intermediate roots.
                None
            },
        },
        blocks: block_data_vec
            .into_iter()
            .map(|d| {
                let mut bi = d.block_input;
                // Set per-block tree root so the executor verifies each block's
                // merkle proofs against the correct tree version.
                bi.expected_tree_root = d.tree_root_before;
                bi
            })
            .collect(),
    };

    let serialized = bincode1::serialize(&batch_input).expect("failed to serialize ZiSK BatchInput");

    // If ZISK_DUMP_DIR is set, write the BatchInput to disk for external proving.
    if let Ok(dump_dir) = std::env::var("ZISK_DUMP_DIR") {
        let path = std::path::Path::new(&dump_dir);
        let _ = std::fs::create_dir_all(path);
        let batch_num = batch_info.batch_number;
        let file_path = path.join(format!("batch_{batch_num}_zisk.bin"));
        // Write in ZiSK stdin format: [len:u64_LE][bincode][padding_to_8]
        let len = serialized.len() as u64;
        let mut buf = Vec::with_capacity(8 + serialized.len() + 8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&serialized);
        let total = 8 + serialized.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat(0u8).take(padding));
        match std::fs::write(&file_path, &buf) {
            Ok(()) => tracing::info!(
                "ZiSK BatchInput dumped: {} ({} bytes, ZiSK stdin format)",
                file_path.display(),
                buf.len()
            ),
            Err(e) => tracing::warn!("Failed to dump ZiSK data: {e}"),
        }
    }

    Ok(serialized)
}
