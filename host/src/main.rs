use anyhow::{bail, Context, Result};
use clap::Parser;
use methods::{guest::{METHOD_ELF, METHOD_ID}, PublicInputs, PublicOutputs};
use risc0_zkvm::{default_prover, ExecutorEnv};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "zk-bbp-poc")]
struct Args {
    /// Path to witness.bin (64 bytes: pre||post big-endian u256s)
    #[arg(long)]
    witness: PathBuf,

    /// Threshold as decimal u128 (e.g., 1000000000000000000 for 1e18)
    #[arg(long)]
    threshold: String,

    /// Optional: write journal.json here
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load witness
    let witness = fs::read(&args.witness)
        .with_context(|| format!("reading {:?}", args.witness))?;
    if witness.len() != 64 {
        bail!("witness must be exactly 64 bytes (pre||post u256)");
    }
    let mut w64 = [0u8; 64];
    w64.copy_from_slice(&witness);

    // Compute commitment = sha256(witness)
    let mut hasher = Sha256::new();
    hasher.update(&w64);
    let commitment: [u8; 32] = hasher.finalize().into();

    // Parse threshold
    let threshold: u128 = args
        .threshold
        .parse()
        .with_context(|| "threshold must be a decimal u128")?;

    // Build public inputs
    let pubin = PublicInputs { threshold, commitment };

    // Build executor env: write pub inputs + witness into the guest stdin
    let env = ExecutorEnv::builder()
        .write(&pubin)?
        .write(&w64)?
        .build()?;

    // Prove
    let prover = default_prover();
    let receipt = prover.prove_elf(env, METHOD_ELF)?;
    // Verify
    receipt.verify(METHOD_ID)?;

    // Decode journal
    let journal: PublicOutputs = receipt.journal.decode()?;

    // Pretty print
    let loss_hi_hex = hex::encode(journal.loss_hi);
    let loss_lo_hex = hex::encode(journal.loss_lo);
    println!("✅ Proof verified");
    println!("• threshold (u128) = {}", journal.threshold);
    println!("• loss (u256)      = 0x{}{}", loss_hi_hex, loss_lo_hex);
    println!("• loss ≥ threshold = {}", journal.loss_ge_threshold);

    if let Some(out) = args.out {
        fs::write(
            out,
            serde_json::to_vec_pretty(&journal).expect("serialize journal"),
        )?;
    }
    Ok(())
}