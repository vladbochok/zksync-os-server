//! Converts server-side block data into a ZiSK `BlockInput` with merkle proofs.
//!
//! Runs a pre-execution pass with REVM to discover all storage reads, then
//! extracts merkle proofs for every accessed slot from the server's merkle tree.

use alloy::consensus::Transaction;
use alloy::eips::Encodable2718;
use alloy::primitives::{Address, B256, Bytes, U256};
use revm::database::CacheDB;
use revm::database_interface::DBErrorMarker;
use revm::primitives::{TxKind, KECCAK_EMPTY};
use revm::state::{AccountInfo, Bytecode};
use revm::{DatabaseRef, ExecuteCommitEvm};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use zk_ee::utils::Bytes32;
use zk_os_forward_system::run::ReadStorageTree;
use zksync_os_interface::traits::{PreimageSource, ReadStorage};
use zksync_os_interface::types::BlockOutput;
use zksync_os_merkle_tree::{MerkleTreeVersion, RocksDBWrapper};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::{DefaultZk, ZKsyncTx, ZkBuilder, ZkContext, ZkSpecId};
use zksync_os_storage_api::{OverriddenStateView, ReadStateHistory, ReplayRecord, ViewState};
use zksync_os_types::{ExecutionVersion, ZkEnvelope, ZkTransaction};

use serde::{Deserialize, Serialize};
use zksync_os_zisk_lib::merkle::{
    self as zisk_merkle, BatchTreeUpdate, NeighborProofEntry, SlotProofEntry, StorageProof,
    TreeLeaf, WriteOp, TREE_DEPTH,
};
use zksync_os_zisk_lib::types::*;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Per-block ZiSK data carried through the pipeline.
#[derive(Serialize, Deserialize, Clone)]
pub struct ZiskBlockData {
    pub block_input: BlockInput,
    pub tree_root_before: B256,
    pub leaf_count_before: u64,
    pub block_number_before: u64,
    pub previous_block_timestamp: u64,
    pub tree_update: Option<BatchTreeUpdate>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Build per-block ZiSK data from server block data, including merkle proofs.
pub fn build_block_data<ReadState: ReadStateHistory>(
    block_output: &BlockOutput,
    replay_record: &ReplayRecord,
    tree_view: &MerkleTreeVersion<RocksDBWrapper>,
    read_state: &ReadState,
) -> anyhow::Result<ZiskBlockData> {
    let ctx = &replay_record.block_context;
    let block_number = ctx.block_number;
    let mut tree = tree_view.clone();
    // Get leaf_count early (stable across versions), but defer root_hash until
    // after proof extraction to avoid race with concurrent tree updates.
    // The underlying RocksDB is shared via Arc; another thread may apply new
    // blocks between root_info() and merkle_proof() calls.
    let (_initial_root, leaf_count) = tree_view.root_info()?;
    let basefee: u64 = ctx.eip1559_basefee.try_into().unwrap_or(u64::MAX);
    let prev_randao = B256::from(ctx.mix_hash.to_be_bytes::<32>());
    let spec_id = spec_id_from_execution_version(ctx.execution_version);

    let transactions = convert_all_txs(&replay_record.transactions);

    // Phase 1: collect addresses + pre-execute to discover storage reads
    let initial_addrs = collect_touched_addresses(replay_record, block_output, ctx.coinbase);
    let mut state_view = read_state.state_view_at(block_number - 1)?;
    // Create a state view with published preimages as overrides.
    // This resolves system contract bytecodes for genesis/upgrade blocks where
    // preimages are published during execution but aren't in the state view at block N-1.
    let all_preimages: Vec<(B256, Vec<u8>)> = block_output.published_preimages
        .iter()
        .chain(&replay_record.force_preimages)
        .cloned()
        .collect();
    let mut state_with_preimages = zksync_os_storage_api::OverriddenStateView::with_preimages(
        state_view.clone(),
        &all_preimages,
    );

    let (accounts_map, mut bytecodes_map, mut bytecodes_out) =
        load_accounts_and_bytecodes(&initial_addrs, &mut state_with_preimages, block_output, replay_record);

    let storage_prestate = load_storage_prestate(&block_output.storage_writes, &mut state_view);

    let (storage_read_keys, extra_addrs, storage_reads) = pre_execute_for_reads(
        ctx, spec_id, basefee, prev_randao, &transactions, block_output,
        &accounts_map, &storage_prestate, &bytecodes_map,
        state_view,
    );

    // Phase 1b: load any newly-discovered accounts (e.g. from CREATE calls)
    let mut all_addrs = initial_addrs;
    let mut seen_addrs: HashSet<Address> = all_addrs.iter().copied().collect();
    let mut state_view = read_state.state_view_at(block_number - 1)?;

    for addr in extra_addrs {
        if seen_addrs.insert(addr) {
            all_addrs.push(addr);
            if let Some(props) = state_view.get_account(addr) {
                let preimage_hash = B256::from(props.bytecode_hash.as_u8_array());
                let observable_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
                if !preimage_hash.is_zero() && !observable_hash.is_zero() {
                    if let Some(padded_code) = state_view.get_preimage(preimage_hash) {
                        let raw_len = props.unpadded_code_len as usize;
                        let raw_code = if raw_len > 0 && raw_len <= padded_code.len() {
                            &padded_code[..raw_len]
                        } else {
                            &padded_code[..]
                        };
                        if !bytecodes_map.contains_key(&observable_hash) {
                            bytecodes_out.push((observable_hash, raw_code.to_vec()));
                            bytecodes_map.insert(observable_hash, Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                        }
                    }
                }
            }
        }
    }

    // Phase 2: extract merkle proofs for all accessed keys
    let (accounts_out, account_preimages, mut storage_proofs) =
        extract_account_proofs(&all_addrs, &mut tree, &mut state_view);

    let mut proven_flat_keys: HashSet<B256> = storage_proofs.iter().map(|(k, _)| *k).collect();

    let storage_out = extract_storage_write_proofs(
        &block_output.storage_writes, &storage_prestate, &mut tree, &mut proven_flat_keys, &mut storage_proofs,
    );

    extract_storage_read_proofs(&storage_read_keys, &mut tree, &mut proven_flat_keys, &mut storage_proofs);

    // Compute actual tree root from extracted proofs. All proofs were extracted from
    // the same tree version (even if RocksDB was updated concurrently), so they're
    // internally consistent. Use the first proof's root recovery as the authoritative root.
    let root_hash = if let Some((key, proof)) = storage_proofs.first() {
        match proof.verify(key) {
            Ok((root, _)) => root,
            Err(_) => tree_view.root_info()?.0,  // fallback
        }
    } else {
        tree_view.root_info()?.0  // no proofs, use tree directly
    };

    // Phase 3: tree update
    let tree_update = if !block_output.storage_writes.is_empty() {
        Some(build_tree_update(&mut tree, &block_output.storage_writes, leaf_count))
    } else {
        None
    };

    // Phase 4: assemble
    let block_hashes = extract_block_hashes(&ctx.block_hashes, block_number);

    let l2_to_l1_logs = extract_l2_to_l1_logs(block_output);

    Ok(ZiskBlockData {
        block_input: BlockInput {
            number: block_number,
            timestamp: ctx.timestamp,
            base_fee: basefee,
            gas_limit: ctx.gas_limit,
            coinbase: ctx.coinbase,
            prev_randao,
            block_header_hash: B256::ZERO,
            storage_proofs,
            account_preimages,
            transactions,
            accounts: accounts_out,
            storage: {
                // Merge write prestates with read values from pre-execution.
                // This ensures REVM's SimpleDB has both read and write slot values.
                let mut all_storage = storage_out;
                let existing: HashSet<(Address, U256)> = all_storage.iter().map(|(a, s, _)| (*a, *s)).collect();
                for (addr, slot, val) in &storage_reads {
                    if !existing.contains(&(*addr, *slot)) {
                        all_storage.push((*addr, *slot, *val));
                    }
                }
                all_storage
            },
            bytecodes: bytecodes_out,
            block_hashes,
            l2_to_l1_logs,
            expected_tree_root: root_hash,
        },
        tree_root_before: root_hash,
        leaf_count_before: leaf_count,
        block_number_before: block_number.saturating_sub(1),
        previous_block_timestamp: replay_record.previous_block_timestamp,
        tree_update,
    })
}

pub fn spec_id_from_execution_version(version: u32) -> ZkSpecId {
    match ExecutionVersion::try_from(version) {
        Ok(ExecutionVersion::V1 | ExecutionVersion::V2 | ExecutionVersion::V3) => ZkSpecId::AtlasV1,
        _ => ZkSpecId::AtlasV2,
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Address collection
// ---------------------------------------------------------------------------

fn collect_touched_addresses(
    replay_record: &ReplayRecord,
    block_output: &BlockOutput,
    coinbase: Address,
) -> Vec<Address> {
    let mut addrs = Vec::new();
    let mut seen = HashSet::new();
    let push = |addr: Address, seen: &mut HashSet<Address>, addrs: &mut Vec<Address>| {
        if seen.insert(addr) { addrs.push(addr); }
    };
    for tx in &replay_record.transactions {
        push(tx.signer(), &mut seen, &mut addrs);
        if let Some(to) = tx.to() { push(to, &mut seen, &mut addrs); }
    }
    push(coinbase, &mut seen, &mut addrs);
    for diff in &block_output.account_diffs {
        push(diff.address, &mut seen, &mut addrs);
    }
    // Include all addresses that have storage writes — these are system contracts
    // (ContractDeployer, NonceHolder, AccountCodeStorage, etc.) that the upgrade
    // transaction modifies. REVM needs their bytecodes to execute the call chain.
    for write in &block_output.storage_writes {
        push(write.account, &mut seen, &mut addrs);
    }
    addrs
}

fn load_accounts_and_bytecodes<S: ViewState>(
    addrs: &[Address],
    state_view: &mut S,
    block_output: &BlockOutput,
    replay_record: &ReplayRecord,
) -> (HashMap<Address, AccountInfo>, HashMap<B256, Bytecode>, Vec<(B256, Vec<u8>)>) {
    let mut accounts = HashMap::new();
    let mut bytecodes_map = HashMap::new();
    let mut bytecodes_out = Vec::new();
    let mut seen_hashes = HashSet::new();

    // Build a lookup for force_preimages (system contract bytecodes from upgrade tx)
    let force_preimage_map: HashMap<B256, &Vec<u8>> = block_output.published_preimages
        .iter()
        .chain(&replay_record.force_preimages)
        .map(|(h, c)| (*h, c))
        .collect();
    if !force_preimage_map.is_empty() {
        tracing::debug!(
            count = force_preimage_map.len(),
            "Force preimages available for bytecode resolution"
        );
    }

    for &addr in addrs {
        if let Some(props) = state_view.get_account(addr) {
            // AccountProperties has two hashes:
            // - bytecode_hash (blake2s256 of padded code) — used for preimage DB lookup
            // - observable_bytecode_hash (keccak256 of raw code) — the EVM-visible code_hash
            // REVM uses keccak256 as code_hash, so we use observable_bytecode_hash.
            let observable_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
            let preimage_hash = B256::from(props.bytecode_hash.as_u8_array());

            let effective = if observable_hash.is_zero() {
                if props.nonce == 0 && props.balance == U256::ZERO { B256::ZERO } else { KECCAK_EMPTY }
            } else {
                observable_hash // keccak256 of raw code — correct for REVM
            };
            accounts.insert(addr, AccountInfo {
                nonce: props.nonce, balance: props.balance, code_hash: effective,
                code: None, account_id: None,
            });
            // Load bytecode: preimage DB stores (blake2s256(padded), padded_code).
            // REVM needs (keccak256(raw), raw_code). Extract raw code by truncating
            // padding using unpadded_code_len from AccountProperties.
            if !preimage_hash.is_zero() && !observable_hash.is_zero() {
                if let Some(padded_code) = state_view.get_preimage(preimage_hash) {
                    // Extract raw EVM code by truncating at unpadded_code_len
                    let raw_len = props.unpadded_code_len as usize;
                    let raw_code = if raw_len > 0 && raw_len <= padded_code.len() {
                        &padded_code[..raw_len]
                    } else {
                        &padded_code
                    };
                    // observable_hash = keccak256(raw_code) — use it as the key
                    if seen_hashes.insert(preimage_hash) {
                        bytecodes_out.push((observable_hash, raw_code.to_vec()));
                        bytecodes_map.insert(observable_hash, Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                    }
                }
            }
        }
    }
    // Load force_preimages (system contract bytecodes from upgrade/genesis) into bytecodes.
    // These must be loaded BEFORE pre-execution so the TrackingDB can trace system calls.
    for (hash, code) in block_output.published_preimages.iter().chain(&replay_record.force_preimages) {
        let keccak_hash = alloy::primitives::keccak256(code);
        if seen_hashes.insert(*hash) {
            bytecodes_out.push((keccak_hash, code.clone()));
            bytecodes_map.insert(keccak_hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
        }
    }
    (accounts, bytecodes_map, bytecodes_out)
}

fn load_storage_prestate(
    writes: &[zksync_os_interface::types::StorageWrite],
    state_view: &mut impl ReadStorage,
) -> HashMap<(Address, U256), U256> {
    let mut prestate = HashMap::new();
    for w in writes {
        let old = state_view.read(w.key).unwrap_or(B256::ZERO);
        prestate.insert((w.account, U256::from_be_bytes(w.account_key.0)), U256::from_be_bytes(old.0));
    }
    prestate
}

// ---------------------------------------------------------------------------
// Phase 1: Pre-execution for read tracking
// ---------------------------------------------------------------------------

/// Returns (storage_read_flat_keys, extra_account_addresses, storage_reads).
/// storage_reads: (address, slot, value) for all storage accessed during pre-execution.
fn pre_execute_for_reads(
    ctx: &zksync_os_interface::types::BlockContext,
    spec_id: ZkSpecId,
    basefee: u64,
    prev_randao: B256,
    transactions: &[TxInput],
    block_output: &BlockOutput,
    accounts: &HashMap<Address, AccountInfo>,
    storage_prestate: &HashMap<(Address, U256), U256>,
    bytecodes: &HashMap<B256, Bytecode>,
    state_view: impl ViewState,
) -> (HashSet<B256>, HashSet<Address>, Vec<(Address, U256, U256)>) {
    let read_keys: RefCell<HashSet<B256>> = RefCell::new(HashSet::new());
    let read_accounts: RefCell<HashSet<Address>> = RefCell::new(HashSet::new());
    let read_storage: RefCell<Vec<(Address, U256, U256)>> = RefCell::new(Vec::new());

    let tracking_db = TrackingDB {
        accounts, storage_prestate,
        state_view: RefCell::new(state_view),
        bytecodes,
        block_hashes: &ctx.block_hashes,
        block_number: ctx.block_number,
        read_keys: &read_keys,
        read_accounts: &read_accounts,
        read_storage: &read_storage,
    };

    let cache_db = CacheDB::new(tracking_db);
    run_pre_execution(
        ctx.chain_id, spec_id, ctx.block_number, ctx.timestamp, ctx.coinbase,
        basefee, ctx.gas_limit, prev_randao, transactions, block_output, cache_db,
    );

    (read_keys.into_inner(), read_accounts.into_inner(), read_storage.into_inner())
}

// ---------------------------------------------------------------------------
// Phase 2: Merkle proof extraction
// ---------------------------------------------------------------------------

fn extract_account_proofs(
    addrs: &[Address],
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    state_view: &mut impl ViewState,
) -> (Vec<(Address, AccountData)>, Vec<(Address, Vec<u8>)>, Vec<(B256, StorageProof)>) {
    let mut accounts_out = Vec::new();
    let mut preimages = Vec::new();
    let mut proofs = Vec::new();

    for &addr in addrs {
        let flat_key = account_flat_key(addr);
        let proof = extract_proof(tree, flat_key);
        proofs.push((flat_key, proof));

        if let Some(props) = state_view.get_account(addr) {
            accounts_out.push((addr, AccountData {
                nonce: props.nonce, balance: props.balance,
                code_hash: B256::from(props.observable_bytecode_hash.as_u8_array()),
            }));
            if let Some(hash_value) = ReadStorage::read(state_view, flat_key) {
                if let Some(preimage) = state_view.get_preimage(hash_value) {
                    preimages.push((addr, preimage));
                }
            }
        } else {
            accounts_out.push((addr, AccountData {
                nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO,
            }));
        }
    }
    (accounts_out, preimages, proofs)
}

fn extract_storage_write_proofs(
    writes: &[zksync_os_interface::types::StorageWrite],
    prestate: &HashMap<(Address, U256), U256>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    proven: &mut HashSet<B256>,
    proofs: &mut Vec<(B256, StorageProof)>,
) -> Vec<(Address, U256, U256)> {
    let mut storage_out = Vec::new();
    for w in writes {
        if proven.insert(w.key) {
            proofs.push((w.key, extract_proof(tree, w.key)));
        }
        let slot = U256::from_be_bytes(w.account_key.0);
        let old = prestate.get(&(w.account, slot)).copied().unwrap_or(U256::ZERO);
        storage_out.push((w.account, slot, old));
    }
    storage_out
}

fn extract_storage_read_proofs(
    read_keys: &HashSet<B256>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    proven: &mut HashSet<B256>,
    proofs: &mut Vec<(B256, StorageProof)>,
) {
    for &key in read_keys {
        if proven.insert(key) {
            proofs.push((key, extract_proof(tree, key)));
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Tree update proof construction
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LeafWithProof {
    index: u64,
    key: B256,
    value: B256,
    next_index: u64,
    siblings: Vec<B256>, // 64 entries
}

fn get_leaf_proof(tree: &mut MerkleTreeVersion<RocksDBWrapper>, idx: u64) -> LeafWithProof {
    let p = tree.merkle_proof(idx);
    LeafWithProof {
        index: p.index,
        key: B256::from(p.leaf.key.as_u8_array()),
        value: B256::from(p.leaf.value.as_u8_array()),
        next_index: p.leaf.next,
        siblings: p.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
    }
}

fn build_tree_update(
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    writes: &[zksync_os_interface::types::StorageWrite],
    leaf_count: u64,
) -> BatchTreeUpdate {
    let mut operations = Vec::new();
    let mut entries = Vec::new();
    let mut leaf_proofs: HashMap<u64, LeafWithProof> = HashMap::new();

    // Track in-memory linked list for correct insert ordering.
    // Maps key → (index, next_index) for both existing and newly inserted leaves.
    let mut key_to_index: BTreeMap<B256, u64> = BTreeMap::new();
    let mut index_to_next: HashMap<u64, u64> = HashMap::new();
    let mut next_free_index = leaf_count;

    // Seed the key map from leaves we discover.
    // Only load proofs for indices that actually exist in the tree (< leaf_count).
    let ensure_leaf = |tree: &mut MerkleTreeVersion<RocksDBWrapper>,
                           idx: u64,
                           leaf_proofs: &mut HashMap<u64, LeafWithProof>,
                           key_to_index: &mut BTreeMap<B256, u64>,
                           index_to_next: &mut HashMap<u64, u64>| {
        if idx < leaf_count && !leaf_proofs.contains_key(&idx) {
            let p = get_leaf_proof(tree, idx);
            key_to_index.insert(p.key, p.index);
            index_to_next.insert(p.index, p.next_index);
            leaf_proofs.insert(idx, p);
        }
    };

    for write in writes {
        let flat_key = B256::from(Bytes32::from_array(write.key.0).as_u8_array());
        let flat_key_bytes32 = Bytes32::from_array(write.key.0);

        if let Some(tree_index) = tree.tree_index(flat_key_bytes32) {
            // Update existing leaf
            operations.push(WriteOp::Update { index: tree_index });
            entries.push((flat_key, write.value));
            ensure_leaf(tree, tree_index, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
        } else {
            // Insert new leaf — find predecessor using in-memory state
            // First check if we already know the predecessor from previous inserts
            let prev_index = if let Some((&prev_key, &prev_idx)) = key_to_index.range(..flat_key).next_back() {
                let _ = prev_key;
                prev_idx
            } else {
                // Fallback to tree (first insert, or predecessor not yet loaded)
                let idx = tree.prev_tree_index(flat_key_bytes32);
                ensure_leaf(tree, idx, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
                idx
            };

            // Ensure predecessor is loaded and get its next
            ensure_leaf(tree, prev_index, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
            let old_next = index_to_next[&prev_index];
            ensure_leaf(tree, old_next, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);

            let this_index = next_free_index;
            next_free_index += 1;

            operations.push(WriteOp::Insert { prev_index });
            entries.push((flat_key, write.value));

            // Update in-memory linked list: prev → this → old_next
            index_to_next.insert(prev_index, this_index);
            index_to_next.insert(this_index, old_next);
            key_to_index.insert(flat_key, this_index);
        }
    }

    // Build sorted_leaves
    let mut sorted_leaves: Vec<(u64, TreeLeaf)> = leaf_proofs
        .values()
        .map(|p| (p.index, TreeLeaf { key: p.key, value: p.value, next_index: p.next_index }))
        .collect();
    sorted_leaves.sort_by_key(|(idx, _)| *idx);

    // Compute intermediate hashes for BOTH the old leaf set AND the new leaf set.
    // apply() calls zip_leaves twice: once to verify old root, once for new root.
    let old_leaf_indices: Vec<u64> = sorted_leaves.iter().map(|(idx, _)| *idx).collect();

    // Simulate apply() to determine the final leaf indices
    let mut sim_next_index = leaf_count;
    let mut new_indices: Vec<u64> = old_leaf_indices.clone();
    for op in &operations {
        if let WriteOp::Insert { .. } = op {
            new_indices.push(sim_next_index);
            sim_next_index += 1;
        }
    }
    new_indices.sort();
    new_indices.dedup();

    // For new leaf indices (>= leaf_count), there are no tree proofs.
    // Their siblings in the tree are empty subtrees. We need to use the
    // tree's hash_at_position() to get the actual sibling hash at each depth.
    // Build a function that resolves sibling hashes for ANY position.
    // Compute separate intermediate hashes for old root verification and new root computation.
    tracing::info!(
        old_leaf_count = old_leaf_indices.len(),
        new_leaf_count = new_indices.len(),
        leaf_count_before = leaf_count,
        leaf_count_after = sim_next_index,
        leaf_proofs_count = leaf_proofs.len(),
        "Computing intermediate hashes for tree update"
    );
    let (intermediate_hashes, intermediate_hashes_new) = compute_intermediate_hashes_full(
        &old_leaf_indices, leaf_count,
        &new_indices, sim_next_index,
        &leaf_proofs, tree,
    );
    tracing::info!(
        old_hashes = intermediate_hashes.len(),
        new_hashes = intermediate_hashes_new.len(),
        "Intermediate hashes computed"
    );

    BatchTreeUpdate {
        operations, entries, sorted_leaves,
        intermediate_hashes,
        intermediate_hashes_new,
        leaf_count_before: leaf_count,
    }
}

/// Compute intermediate hashes by simulating the zip_leaves consumption order.
/// Uses a prebuilt index for O(1) sibling lookup instead of O(n) scan.
fn compute_intermediate_hashes(
    leaf_indices: &[u64],
    leaf_proofs: &HashMap<u64, LeafWithProof>,
    leaf_count: u64,
) -> Vec<B256> {
    // Build index: for each (depth, node_idx_on_level) → leaf proof index
    // A leaf T at depth D has node T >> D. siblings[D] is sibling of that node.
    let mut sibling_index: HashMap<(u8, u64), u64> = HashMap::new();
    for proof in leaf_proofs.values() {
        for d in 0..TREE_DEPTH {
            let node = proof.index >> d;
            sibling_index.entry((d, node)).or_insert(proof.index);
        }
    }

    let mut result = Vec::new();
    let mut node_indices: Vec<u64> = leaf_indices.to_vec();
    let mut last_idx_on_level = leaf_count - 1;

    for depth in 0..TREE_DEPTH {
        let mut i = 0;
        let mut next_level = Vec::new();

        while i < node_indices.len() {
            let idx = node_indices[i];
            if idx % 2 == 1 {
                // Odd: needs left sibling
                let leaf_idx = sibling_index[&(depth, idx)];
                result.push(leaf_proofs[&leaf_idx].siblings[depth as usize]);
                next_level.push(idx / 2);
                i += 1;
            } else if node_indices.get(i + 1).copied() == Some(idx + 1) {
                // Both present
                next_level.push(idx / 2);
                i += 2;
            } else {
                if idx != last_idx_on_level {
                    let leaf_idx = sibling_index[&(depth, idx)];
                    result.push(leaf_proofs[&leaf_idx].siblings[depth as usize]);
                }
                next_level.push(idx / 2);
                i += 1;
            }
        }
        node_indices = next_level;
        last_idx_on_level /= 2;
    }
    result
}

/// Compute intermediate hashes for both old and new leaf sets.
/// Uses the tree directly to resolve sibling hashes at any position.
fn compute_intermediate_hashes_full(
    old_indices: &[u64],
    old_leaf_count: u64,
    new_indices: &[u64],
    new_leaf_count: u64,
    leaf_proofs: &HashMap<u64, LeafWithProof>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
) -> (Vec<B256>, Vec<B256>) {
    let empty_hashes = zisk_merkle::empty_subtree_hashes_vec();

    // Build sibling cache from already-loaded proofs.
    // Key: (depth, node_index_at_that_depth) → hash of that node
    let mut sibling_cache: HashMap<(u8, u64), B256> = HashMap::new();
    for proof in leaf_proofs.values() {
        for d in 0..TREE_DEPTH {
            let sibling_node = (proof.index >> d) ^ 1;
            sibling_cache.entry((d, sibling_node)).or_insert(proof.siblings[d as usize]);
        }
    }

    // Function to resolve sibling hash, loading from tree if necessary.
    // We pass tree as a mutable reference so we can load new proofs on demand.
    let mut resolve_sibling = |depth: u8, sibling_node: u64, leaf_count: u64| -> B256 {
        // Check cache first
        if let Some(&h) = sibling_cache.get(&(depth, sibling_node)) {
            return h;
        }
        // Beyond tree → empty subtree
        let range_start = sibling_node << depth;
        if range_start >= leaf_count {
            return empty_hashes[depth as usize];
        }
        // Load a proof from a leaf in this subtree to populate cache
        let leaf_in_subtree = range_start.min(old_leaf_count.saturating_sub(1));
        if leaf_in_subtree < old_leaf_count {
            let p = get_leaf_proof(tree, leaf_in_subtree);
            for d in 0..TREE_DEPTH {
                let sn = (p.index >> d) ^ 1;
                sibling_cache.entry((d, sn)).or_insert(p.siblings[d as usize]);
            }
            if let Some(&h) = sibling_cache.get(&(depth, sibling_node)) {
                return h;
            }
        }
        empty_hashes[depth as usize]
    };

    // Simulate zip_leaves for old leaf set
    let mut old_hashes = Vec::new();
    {
        let mut node_indices: Vec<u64> = old_indices.to_vec();
        let mut last_idx = old_leaf_count - 1;
        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level = Vec::new();
            while i < node_indices.len() {
                let idx = node_indices[i];
                if idx % 2 == 1 {
                    old_hashes.push(resolve_sibling(depth, idx - 1, old_leaf_count));
                    next_level.push(idx / 2);
                    i += 1;
                } else if node_indices.get(i + 1).copied() == Some(idx + 1) {
                    next_level.push(idx / 2);
                    i += 2;
                } else {
                    if idx != last_idx {
                        old_hashes.push(resolve_sibling(depth, idx + 1, old_leaf_count));
                    }
                    next_level.push(idx / 2);
                    i += 1;
                }
            }
            node_indices = next_level;
            last_idx /= 2;
        }
    }

    // Simulate zip_leaves for new leaf set
    let mut new_hashes = Vec::new();
    {
        let mut node_indices: Vec<u64> = new_indices.to_vec();
        let mut last_idx = new_leaf_count - 1;
        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level = Vec::new();
            while i < node_indices.len() {
                let idx = node_indices[i];
                if idx % 2 == 1 {
                    new_hashes.push(resolve_sibling(depth, idx - 1, new_leaf_count));
                    next_level.push(idx / 2);
                    i += 1;
                } else if node_indices.get(i + 1).copied() == Some(idx + 1) {
                    next_level.push(idx / 2);
                    i += 2;
                } else {
                    if idx != last_idx {
                        new_hashes.push(resolve_sibling(depth, idx + 1, new_leaf_count));
                    }
                    next_level.push(idx / 2);
                    i += 1;
                }
            }
            node_indices = next_level;
            last_idx /= 2;
        }
    }

    (old_hashes, new_hashes)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn account_flat_key(account: Address) -> B256 {
    zisk_merkle::derive_account_properties_key(&account.into_array())
}

fn extract_proof(tree: &mut MerkleTreeVersion<RocksDBWrapper>, flat_key: B256) -> StorageProof {
    let key_bytes = Bytes32::from_array(flat_key.0);
    if let Some(tree_index) = tree.tree_index(key_bytes) {
        let p = tree.merkle_proof(tree_index);
        StorageProof::Existing(SlotProofEntry {
            index: p.index,
            value: B256::from(p.leaf.value.as_u8_array()),
            next_index: p.leaf.next,
            siblings: p.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
        })
    } else {
        let prev_index = tree.prev_tree_index(key_bytes);
        let left = tree.merkle_proof(prev_index);
        let right = tree.merkle_proof(left.leaf.next);
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry {
                entry: SlotProofEntry {
                    index: left.index,
                    value: B256::from(left.leaf.value.as_u8_array()),
                    next_index: left.leaf.next,
                    siblings: left.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
                },
                leaf_key: B256::from(left.leaf.key.as_u8_array()),
            },
            right_neighbor: NeighborProofEntry {
                entry: SlotProofEntry {
                    index: right.index,
                    value: B256::from(right.leaf.value.as_u8_array()),
                    next_index: right.leaf.next,
                    siblings: right.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
                },
                leaf_key: B256::from(right.leaf.key.as_u8_array()),
            },
        }
    }
}

fn extract_block_hashes(
    hashes: &zksync_os_interface::types::BlockHashes,
    block_number: u64,
) -> Vec<(u64, B256)> {
    hashes.0.iter().enumerate().filter_map(|(i, hash)| {
        let h = B256::from(hash.to_be_bytes::<32>());
        if !h.is_zero() && block_number > 0 {
            let num = block_number.saturating_sub(256 - i as u64);
            if num > 0 { Some((num, h)) } else { None }
        } else { None }
    }).collect()
}

fn extract_l2_to_l1_logs(block_output: &BlockOutput) -> Vec<L2ToL1LogEntry> {
    let mut logs = Vec::new();
    for tx_result in block_output.tx_results.iter().flatten() {
        for log in &tx_result.l2_to_l1_logs {
            logs.push(L2ToL1LogEntry {
                l2_shard_id: log.log.l2_shard_id,
                is_service: log.log.is_service,
                tx_number_in_block: log.log.tx_number_in_block,
                sender: log.log.sender,
                key: log.log.key,
                value: log.log.value,
            });
        }
    }
    logs
}

// ---------------------------------------------------------------------------
// Transaction conversion
// ---------------------------------------------------------------------------

fn convert_all_txs(transactions: &[ZkTransaction]) -> Vec<TxInput> {
    transactions.iter().filter_map(convert_tx).collect()
}

fn convert_tx(tx: &ZkTransaction) -> Option<TxInput> {
    let caller = tx.signer();
    let encoded_bytes = tx.envelope().encoded_2718();

    let (gas_price, gas_priority_fee, value, data, chain_id, tx_type, mint, rr, is_l1, l1_hash) =
        match tx.envelope() {
            ZkEnvelope::System(_) => return None,
            ZkEnvelope::L2(l2) => (
                l2.max_fee_per_gas(), l2.max_priority_fee_per_gas(),
                l2.value(), l2.input().to_vec(), l2.chain_id(),
                l2.tx_type() as u8, None, None, false, None,
            ),
            ZkEnvelope::L1(l1) => {
                let i = &l1.inner;
                (l1.max_fee_per_gas(), l1.max_priority_fee_per_gas(),
                 i.value(), i.input().to_vec(), None, 0x7f,
                 Some(U256::from_limbs(i.to_mint.into_limbs())),
                 Some(i.refund_recipient), true, Some(i.hash))
            }
            ZkEnvelope::Upgrade(u) => {
                let i = &u.inner;
                (0, None, i.value(), i.input().to_vec(), None, 0x7e,
                 Some(U256::from_limbs(i.to_mint.into_limbs())),
                 Some(i.refund_recipient), true, Some(i.hash))
            }
        };

    Some(TxInput {
        caller, gas_limit: tx.gas_limit(), gas_price,
        gas_priority_fee, // preserve None when absent (#8)
        to: tx.to(), value, data,
        nonce: tx.nonce(), chain_id, tx_type,
        gas_used_override: None, force_fail: false,
        mint, refund_recipient: rr,
        is_l1_tx: is_l1, l1_tx_hash: l1_hash,
        signed_tx_bytes: Some(encoded_bytes),
    })
}

// ---------------------------------------------------------------------------
// Tracking database for pre-execution
// ---------------------------------------------------------------------------

struct TrackingDB<'a, S> {
    accounts: &'a HashMap<Address, AccountInfo>,
    storage_prestate: &'a HashMap<(Address, U256), U256>,
    state_view: RefCell<S>,
    bytecodes: &'a HashMap<B256, Bytecode>,
    block_hashes: &'a zksync_os_interface::types::BlockHashes,
    block_number: u64,
    read_keys: &'a RefCell<HashSet<B256>>,
    read_accounts: &'a RefCell<HashSet<Address>>,
    /// Storage reads captured during pre-execution: (address, slot, value).
    /// Used to populate block.storage for the unverified execution path.
    read_storage: &'a RefCell<Vec<(Address, U256, U256)>>,
}

#[derive(Debug)]
struct TrackingDBError;
impl core::fmt::Display for TrackingDBError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "tracking db") }
}
impl std::error::Error for TrackingDBError {}
impl DBErrorMarker for TrackingDBError {}

impl<S: ViewState> DatabaseRef for TrackingDB<'_, S> {
    type Error = TrackingDBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.read_accounts.borrow_mut().insert(address);
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecodes.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let flat_key = zisk_merkle::derive_flat_storage_key(&address.into_array(), &B256::from(index.to_be_bytes::<32>()));
        self.read_keys.borrow_mut().insert(flat_key);

        let val = if let Some(&val) = self.storage_prestate.get(&(address, index)) {
            val
        } else {
            self.state_view.borrow_mut().read(flat_key)
                .map(|v| U256::from_be_bytes(v.0))
                .unwrap_or(U256::ZERO)
        };
        // Capture read for SimpleDB storage population
        self.read_storage.borrow_mut().push((address, index, val));
        Ok(val)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        if self.block_number > 0 && number < self.block_number {
            let idx = 256usize.saturating_sub((self.block_number - number) as usize);
            if idx < 256 {
                return Ok(B256::from(self.block_hashes.0[idx].to_be_bytes::<32>()));
            }
        }
        Ok(B256::ZERO)
    }
}

fn run_pre_execution<DB: DatabaseRef>(
    chain_id: u64, spec_id: ZkSpecId, block_number: u64, timestamp: u64,
    coinbase: Address, basefee: u64, gas_limit: u64, prev_randao: B256,
    transactions: &[TxInput], block_output: &BlockOutput, mut cache_db: CacheDB<DB>,
) where DB::Error: core::fmt::Debug {
    let mut evm = <ZkContext<_>>::default()
        .with_db(&mut cache_db)
        .modify_cfg_chained(|cfg| { cfg.chain_id = chain_id; cfg.spec = spec_id; })
        .modify_block_chained(|blk| {
            blk.number = U256::from(block_number); blk.timestamp = U256::from(timestamp);
            blk.beneficiary = coinbase; blk.basefee = basefee;
            blk.gas_limit = gas_limit; blk.prevrandao = Some(prev_randao);
        })
        .build_zk();

    for (i, tx_input) in transactions.iter().enumerate() {
        let (gas_override, force_fail) = match block_output.tx_results.get(i) {
            Some(Ok(o)) => (Some(o.gas_used), false),
            Some(Err(_)) => (Some(0), true),
            None => (None, false),
        };
        let kind = match tx_input.to { Some(a) => TxKind::Call(a), None => TxKind::Create };
        let mut b = revm::context::TxEnv::builder()
            .caller(tx_input.caller).gas_limit(tx_input.gas_limit)
            .gas_price(tx_input.gas_price).kind(kind).value(tx_input.value)
            .data(Bytes::copy_from_slice(&tx_input.data)).nonce(tx_input.nonce)
            .tx_type(Some(tx_input.tx_type)).chain_id(tx_input.chain_id).blob_hashes(vec![]);
        if let Some(fee) = tx_input.gas_priority_fee { b = b.gas_priority_fee(Some(fee)); }
        let tx: ZKsyncTx<revm::context::TxEnv> = ZKsyncTxBuilder::new()
            .base(b).mint(tx_input.mint.unwrap_or_default())
            .refund_recipient(tx_input.refund_recipient)
            .gas_used_override(gas_override).force_fail(force_fail)
            .build().expect("tx build failed");
        let _ = evm.transact_commit(tx);
    }
}
