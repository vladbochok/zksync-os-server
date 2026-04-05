//! ZiSK SNARK proof generation.
//!
//! Runs the ZiSK pipeline (STARK aggregation → SNARK wrapping) as external
//! subprocesses managed by `cargo-zisk`. Work directories are cleaned up on
//! success and preserved on failure for debugging.
//!
//! Follows the same patterns as `fri_proof_verifier.rs`:
//! - Typed error enum with structured fields
//! - Path validation at construction time (fail-fast)
//! - Subprocess stderr captured for diagnostics

use crate::prover_api::zisk_proof_constants::{ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Configuration for the ZiSK prover (extracted from ProverInputGeneratorConfig).
pub struct ZiskProverConfig {
    pub binary: Option<String>,
    pub elf_path: Option<String>,
    pub proving_key: Option<String>,
    pub proving_key_snark: Option<String>,
    pub work_dir: Option<String>,
}

/// Validated ZiSK SNARK proof output.
pub struct ZiskSnarkOutput {
    /// 768-byte Plonk proof (24 BN254 points).
    pub proof: Vec<u8>,
    /// 256-byte public values (8 uint256 slots; first 32 bytes = batch commitment).
    pub public_values: Vec<u8>,
}

/// Errors from ZiSK proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ZiskProverError {
    #[error("ZiSK not configured: {0}")]
    NotConfigured(&'static str),

    #[error("failed to create work directory {path}: {source}")]
    WorkDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write input file: {0}")]
    WriteInput(std::io::Error),

    #[error("STARK aggregation failed for batch {batch}: {detail}")]
    StarkFailed { batch: u64, detail: String },

    #[error("SNARK wrapping failed for batch {batch}: {detail}")]
    SnarkFailed { batch: u64, detail: String },

    #[error("failed to read proof output {path}: {source}")]
    ReadOutput {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid proof output: {0}")]
    InvalidOutput(String),

    #[error("proof output file not generated: {0}")]
    MissingOutput(PathBuf),
}

/// ZiSK prover with validated configuration.
///
/// All paths are checked at construction time via [`from_config`]. Proof
/// generation creates a per-batch work directory that is cleaned up on
/// success and preserved on failure for debugging.
///
/// [`from_config`]: ZiskProver::from_config
#[derive(Clone)]
pub struct ZiskProver {
    binary: PathBuf,
    elf_path: PathBuf,
    proving_key: PathBuf,
    proving_key_snark: PathBuf,
    work_dir_base: PathBuf,
}

impl ZiskProver {
    /// Create a prover, validating that all required paths exist.
    ///
    /// Returns `Err` if any required field is `None` or points to a missing file.
    /// Called at server startup to fail fast on misconfiguration.
    pub fn from_config(config: &ZiskProverConfig) -> Result<Self, ZiskProverError> {
        let binary = require_path(&config.binary, "zisk_binary")?;
        let elf_path = require_path(&config.elf_path, "zisk_elf_path")?;
        let proving_key = require_path(&config.proving_key, "zisk_proving_key")?;
        let proving_key_snark =
            require_path(&config.proving_key_snark, "zisk_proving_key_snark")?;
        let work_dir_base = PathBuf::from(
            config
                .work_dir
                .as_deref()
                .unwrap_or(crate::prover_api::zisk_data_cache::DEFAULT_ZISK_WORK_DIR),
        );

        Ok(Self {
            binary,
            elf_path,
            proving_key,
            proving_key_snark,
            work_dir_base,
        })
    }

    /// Generate a ZiSK SNARK proof for the given batch.
    ///
    /// Runs STARK aggregation followed by SNARK wrapping as subprocesses.
    /// The work directory (`{work_dir_base}/batch_{batch_number}`) is cleaned
    /// up on success and preserved on failure for debugging.
    pub fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
    ) -> Result<ZiskSnarkOutput, ZiskProverError> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));

        // Clean up leftover from a previous attempt.
        let _ = std::fs::remove_dir_all(&work_dir);
        std::fs::create_dir_all(&work_dir).map_err(|e| ZiskProverError::WorkDir {
            path: work_dir.clone(),
            source: e,
        })?;

        let result = self.run_pipeline(zisk_bincode, batch_number, &work_dir);

        let elapsed = start.elapsed();
        match &result {
            Ok(_) => {
                tracing::info!(
                    batch_number,
                    elapsed_secs = elapsed.as_secs(),
                    "ZiSK SNARK proof generated"
                );
                if let Err(e) = std::fs::remove_dir_all(&work_dir) {
                    tracing::warn!(
                        batch_number,
                        path = %work_dir.display(),
                        "failed to clean up work directory: {e}"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    batch_number,
                    elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(),
                    "ZiSK proof generation failed: {e}"
                );
            }
        }

        result
    }

    /// Internal pipeline: write input → STARK aggregation → SNARK wrapping → parse output.
    fn run_pipeline(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        work_dir: &Path,
    ) -> Result<ZiskSnarkOutput, ZiskProverError> {
        let input_path = work_dir.join("input.bin");
        write_zisk_input(&input_path, zisk_bincode)?;

        let stark_dir = work_dir.join("stark");
        self.run_stark_aggregation(batch_number, &input_path, &stark_dir)?;

        let vadcop_path = stark_dir.join("vadcop_final_proof.bin");
        if !vadcop_path.exists() {
            return Err(ZiskProverError::MissingOutput(vadcop_path));
        }

        let snark_dir = work_dir.join("snark");
        self.run_snark_wrapping(batch_number, &vadcop_path, &snark_dir)?;

        let snark_proof_path = snark_dir.join("final_snark_proof.bin");
        if !snark_proof_path.exists() {
            return Err(ZiskProverError::MissingOutput(snark_proof_path));
        }

        parse_snark_output(&snark_proof_path)
    }

    /// Run `cargo-zisk prove` for STARK aggregation.
    fn run_stark_aggregation(
        &self,
        batch_number: u64,
        input_path: &Path,
        stark_dir: &Path,
    ) -> Result<(), ZiskProverError> {
        std::fs::create_dir_all(stark_dir.join("proofs")).map_err(|e| {
            ZiskProverError::WorkDir {
                path: stark_dir.to_path_buf(),
                source: e,
            }
        })?;

        tracing::info!(batch_number, "Running ZiSK STARK aggregation...");
        let output = Command::new(&self.binary)
            .args([
                "prove",
                "-e", &path_str(&self.elf_path),
                "-i", &path_str(input_path),
                "-k", &path_str(&self.proving_key),
                "-o", &path_str(stark_dir),
                "--emulator", "--aggregation", "--save-proofs", "-v",
            ])
            .output()
            .map_err(|e| ZiskProverError::StarkFailed {
                batch: batch_number,
                detail: format!("failed to spawn {}: {e}", self.binary.display()),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ZiskProverError::StarkFailed {
                batch: batch_number,
                detail: stderr_tail(&stderr),
            });
        }
        Ok(())
    }

    /// Run `cargo-zisk prove-snark` for SNARK wrapping.
    fn run_snark_wrapping(
        &self,
        batch_number: u64,
        vadcop_path: &Path,
        snark_dir: &Path,
    ) -> Result<(), ZiskProverError> {
        std::fs::create_dir_all(snark_dir).map_err(|e| ZiskProverError::WorkDir {
            path: snark_dir.to_path_buf(),
            source: e,
        })?;

        tracing::info!(batch_number, "Running ZiSK SNARK wrapping...");
        let output = Command::new(&self.binary)
            .args([
                "prove-snark",
                "--proof", &path_str(vadcop_path),
                "--elf", &path_str(&self.elf_path),
                "--proving-key-snark", &path_str(&self.proving_key_snark),
                "-o", &path_str(snark_dir),
                "-v",
            ])
            .output()
            .map_err(|e| ZiskProverError::SnarkFailed {
                batch: batch_number,
                detail: format!("failed to spawn {}: {e}", self.binary.display()),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ZiskProverError::SnarkFailed {
                batch: batch_number,
                detail: stderr_tail(&stderr),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a config path exists, returning a PathBuf.
fn require_path(opt: &Option<String>, field: &'static str) -> Result<PathBuf, ZiskProverError> {
    let s = opt.as_deref().ok_or(ZiskProverError::NotConfigured(field))?;
    let p = PathBuf::from(s);
    if !p.exists() {
        return Err(ZiskProverError::NotConfigured(Box::leak(
            format!("{field} path does not exist: {}", p.display()).into_boxed_str(),
        )));
    }
    Ok(p)
}

/// Convert Path to &str for command args (lossy on non-UTF8).
fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Return the last 1000 chars of stderr for error messages.
fn stderr_tail(stderr: &str) -> String {
    stderr[stderr.len().saturating_sub(1000)..].to_string()
}

/// Write ZiSK stdin format: `[len:u64_LE][bincode][padding_to_8B]`.
fn write_zisk_input(path: &Path, bincode: &[u8]) -> Result<(), ZiskProverError> {
    let len = bincode.len() as u64;
    let mut buf = Vec::with_capacity(8 + bincode.len() + 8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bincode);
    let padding = (8 - ((8 + bincode.len()) % 8)) % 8;
    buf.extend(std::iter::repeat(0u8).take(padding));
    std::fs::write(path, &buf).map_err(ZiskProverError::WriteInput)
}

/// Parse the ZiSK `final_snark_proof.bin` output.
///
/// Format: `[proof_len:u64_LE][proof_bytes][pv_len:u64_LE][pv_bytes]`
fn parse_snark_output(path: &Path) -> Result<ZiskSnarkOutput, ZiskProverError> {
    let data = std::fs::read(path).map_err(|e| ZiskProverError::ReadOutput {
        path: path.to_path_buf(),
        source: e,
    })?;

    let min_size = 8 + ZISK_SNARK_PROOF_BYTES + 8 + ZISK_PUBLIC_VALUES_BYTES;
    if data.len() < min_size {
        return Err(ZiskProverError::InvalidOutput(format!(
            "file too small: {} bytes, expected >= {min_size}",
            data.len()
        )));
    }

    let proof_len = u64::from_le_bytes(
        data[0..8]
            .try_into()
            .map_err(|_| ZiskProverError::InvalidOutput("proof length header".into()))?,
    ) as usize;
    if proof_len != ZISK_SNARK_PROOF_BYTES {
        return Err(ZiskProverError::InvalidOutput(format!(
            "proof length {proof_len}, expected {ZISK_SNARK_PROOF_BYTES}"
        )));
    }

    let pv_offset = 8 + ZISK_SNARK_PROOF_BYTES;
    let pv_len = u64::from_le_bytes(
        data[pv_offset..pv_offset + 8]
            .try_into()
            .map_err(|_| ZiskProverError::InvalidOutput("pv length header".into()))?,
    ) as usize;
    if pv_len != ZISK_PUBLIC_VALUES_BYTES {
        return Err(ZiskProverError::InvalidOutput(format!(
            "public values length {pv_len}, expected {ZISK_PUBLIC_VALUES_BYTES}"
        )));
    }

    Ok(ZiskSnarkOutput {
        proof: data[8..8 + ZISK_SNARK_PROOF_BYTES].to_vec(),
        public_values: data[pv_offset + 8..pv_offset + 8 + ZISK_PUBLIC_VALUES_BYTES].to_vec(),
    })
}
