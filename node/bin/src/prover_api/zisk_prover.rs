//! ZiSK SNARK proof generation.
//!
//! Runs the ZiSK pipeline (STARK aggregation → SNARK wrapping) as external
//! subprocesses. Manages work directories and cleans up after completion.

use crate::config::ProverInputGeneratorConfig;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Expected proof output sizes (invariants of the ZiSK Plonk verifier).
const ZISK_SNARK_PROOF_BYTES: usize = 768;
const ZISK_PUBLIC_VALUES_BYTES: usize = 256;

/// Validated ZiSK SNARK proof output.
pub struct ZiskSnarkOutput {
    pub proof: Vec<u8>,
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

/// Validated configuration for ZiSK proving (all paths checked at construction).
#[derive(Clone)]
pub struct ZiskProver {
    binary: PathBuf,
    elf_path: PathBuf,
    proving_key: PathBuf,
    proving_key_snark: PathBuf,
    work_dir_base: PathBuf,
}

impl ZiskProver {
    /// Create a prover from config, validating all paths exist.
    pub fn from_config(config: &ProverInputGeneratorConfig) -> Result<Self, ZiskProverError> {
        let binary = config
            .zisk_binary
            .as_deref()
            .ok_or(ZiskProverError::NotConfigured("zisk_binary"))?;
        let elf_path = config
            .zisk_elf_path
            .as_deref()
            .ok_or(ZiskProverError::NotConfigured("zisk_elf_path"))?;
        let proving_key = config
            .zisk_proving_key
            .as_deref()
            .ok_or(ZiskProverError::NotConfigured("zisk_proving_key"))?;
        let proving_key_snark = config
            .zisk_proving_key_snark
            .as_deref()
            .ok_or(ZiskProverError::NotConfigured("zisk_proving_key_snark"))?;
        let work_dir_base = config
            .zisk_work_dir
            .as_deref()
            .unwrap_or("/tmp/zisk_proofs");

        // Validate paths exist at startup, not at proof time.
        let binary = PathBuf::from(binary);
        let elf_path = PathBuf::from(elf_path);
        let proving_key = PathBuf::from(proving_key);
        let proving_key_snark = PathBuf::from(proving_key_snark);
        let work_dir_base = PathBuf::from(work_dir_base);

        for (name, path) in [
            ("binary", &binary),
            ("elf_path", &elf_path),
            ("proving_key", &proving_key),
            ("proving_key_snark", &proving_key_snark),
        ] {
            if !path.exists() {
                return Err(ZiskProverError::NotConfigured(
                    // Leak a &'static str for the error message. This only happens at startup.
                    Box::leak(format!("zisk.{name} path does not exist: {}", path.display()).into()),
                ));
            }
        }

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
    /// Runs STARK aggregation + SNARK wrapping as subprocesses.
    /// Work directory is cleaned up on success.
    pub fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
    ) -> Result<ZiskSnarkOutput, ZiskProverError> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));

        // Clean up any leftover from a previous attempt.
        let _ = std::fs::remove_dir_all(&work_dir);
        std::fs::create_dir_all(&work_dir).map_err(|e| ZiskProverError::WorkDir {
            path: work_dir.clone(),
            source: e,
        })?;

        let result = self.generate_proof_inner(zisk_bincode, batch_number, &work_dir);

        let elapsed = start.elapsed();
        match &result {
            Ok(_) => {
                tracing::info!(
                    batch_number,
                    elapsed_secs = elapsed.as_secs(),
                    "ZiSK SNARK proof generated"
                );
                // Clean up work directory on success.
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
                // Leave work directory for debugging on failure.
            }
        }

        result
    }

    fn generate_proof_inner(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        work_dir: &Path,
    ) -> Result<ZiskSnarkOutput, ZiskProverError> {
        // Write input file.
        let input_path = work_dir.join("input.bin");
        write_zisk_input(&input_path, zisk_bincode)?;

        // STARK aggregation.
        let stark_dir = work_dir.join("stark");
        std::fs::create_dir_all(stark_dir.join("proofs")).map_err(|e| {
            ZiskProverError::WorkDir {
                path: stark_dir.clone(),
                source: e,
            }
        })?;

        tracing::info!(batch_number, "Running ZiSK STARK aggregation...");
        run_subprocess(
            &self.binary,
            &[
                "prove",
                "-e",
                self.elf_path.to_str().unwrap_or(""),
                "-i",
                input_path.to_str().unwrap_or(""),
                "-k",
                self.proving_key.to_str().unwrap_or(""),
                "-o",
                stark_dir.to_str().unwrap_or(""),
                "--emulator",
                "--aggregation",
                "--save-proofs",
                "-v",
            ],
            batch_number,
            "STARK aggregation",
        )?;

        let vadcop_path = stark_dir.join("vadcop_final_proof.bin");
        if !vadcop_path.exists() {
            return Err(ZiskProverError::MissingOutput(vadcop_path));
        }

        // SNARK wrapping.
        let snark_dir = work_dir.join("snark");
        std::fs::create_dir_all(&snark_dir).map_err(|e| ZiskProverError::WorkDir {
            path: snark_dir.clone(),
            source: e,
        })?;

        tracing::info!(batch_number, "Running ZiSK SNARK wrapping...");
        run_subprocess(
            &self.binary,
            &[
                "prove-snark",
                "--proof",
                vadcop_path.to_str().unwrap_or(""),
                "--elf",
                self.elf_path.to_str().unwrap_or(""),
                "--proving-key-snark",
                self.proving_key_snark.to_str().unwrap_or(""),
                "-o",
                snark_dir.to_str().unwrap_or(""),
                "-v",
            ],
            batch_number,
            "SNARK wrapping",
        )?;

        // Parse output.
        let snark_proof_path = snark_dir.join("final_snark_proof.bin");
        if !snark_proof_path.exists() {
            return Err(ZiskProverError::MissingOutput(snark_proof_path));
        }

        parse_snark_output(&snark_proof_path)
    }
}

/// Write ZiSK stdin format: [len:u64_LE][bincode][padding_to_8B].
fn write_zisk_input(path: &Path, bincode: &[u8]) -> Result<(), ZiskProverError> {
    let len = bincode.len() as u64;
    let mut buf = Vec::with_capacity(8 + bincode.len() + 8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bincode);
    let padding = (8 - ((8 + bincode.len()) % 8)) % 8;
    buf.extend(std::iter::repeat(0u8).take(padding));
    std::fs::write(path, &buf).map_err(ZiskProverError::WriteInput)
}

/// Run a cargo-zisk subprocess and check for success.
fn run_subprocess(
    binary: &Path,
    args: &[&str],
    batch_number: u64,
    step_name: &str,
) -> Result<(), ZiskProverError> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|e| ZiskProverError::StarkFailed {
            batch: batch_number,
            detail: format!("failed to spawn {}: {e}", binary.display()),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = &stderr[stderr.len().saturating_sub(1000)..];
        return Err(if step_name.contains("STARK") {
            ZiskProverError::StarkFailed {
                batch: batch_number,
                detail: tail.to_string(),
            }
        } else {
            ZiskProverError::SnarkFailed {
                batch: batch_number,
                detail: tail.to_string(),
            }
        });
    }

    Ok(())
}

/// Parse the ZiSK final_snark_proof.bin output format.
/// Format: [proof_len:u64_LE][proof_bytes][pv_len:u64_LE][pv_bytes]
fn parse_snark_output(path: &Path) -> Result<ZiskSnarkOutput, ZiskProverError> {
    let data = std::fs::read(path).map_err(|e| ZiskProverError::ReadOutput {
        path: path.to_path_buf(),
        source: e,
    })?;

    let min_size = 8 + ZISK_SNARK_PROOF_BYTES + 8 + ZISK_PUBLIC_VALUES_BYTES;
    if data.len() < min_size {
        return Err(ZiskProverError::InvalidOutput(format!(
            "output file too small: {} bytes, expected at least {min_size}",
            data.len()
        )));
    }

    let proof_len =
        u64::from_le_bytes(data[0..8].try_into().map_err(|_| {
            ZiskProverError::InvalidOutput("failed to read proof length".into())
        })?) as usize;

    if proof_len != ZISK_SNARK_PROOF_BYTES {
        return Err(ZiskProverError::InvalidOutput(format!(
            "proof length {proof_len}, expected {ZISK_SNARK_PROOF_BYTES}"
        )));
    }

    let proof = data[8..8 + ZISK_SNARK_PROOF_BYTES].to_vec();
    let pv_offset = 8 + ZISK_SNARK_PROOF_BYTES;

    let pv_len = u64::from_le_bytes(
        data[pv_offset..pv_offset + 8]
            .try_into()
            .map_err(|_| ZiskProverError::InvalidOutput("failed to read pv length".into()))?,
    ) as usize;

    if pv_len != ZISK_PUBLIC_VALUES_BYTES {
        return Err(ZiskProverError::InvalidOutput(format!(
            "public values length {pv_len}, expected {ZISK_PUBLIC_VALUES_BYTES}"
        )));
    }

    let public_values = data[pv_offset + 8..pv_offset + 8 + ZISK_PUBLIC_VALUES_BYTES].to_vec();

    Ok(ZiskSnarkOutput {
        proof,
        public_values,
    })
}
