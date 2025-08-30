use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use methods::{PublicInputs, PublicOutputs, METHOD_ELF, METHOD_ID};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "zk-bbp-poc-calldata")]
struct Args {
    /// Public RPC endpoint (e.g., https://eth.llamarpc.com)
    #[arg(long)]
    rpc: String,

    /// Asset (ERC-20) and Target addresses (0x-prefixed, 20 bytes)
    #[arg(long)]
    asset: String,
    #[arg(long)]
    target: String,

    /// Block number to use as the pinned state (decimal)
    #[arg(long)]
    block: u64,

    /// Path to PoC calldata (hex string file starting with 0x, or raw bytes)
    #[arg(long)]
    calldata: PathBuf,

    /// Threshold as decimal u128 (e.g., 1000000000000000000 for 1e18)
    #[arg(long)]
    threshold: String,

    /// Optional: write journal.json here
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let client = Client::new();

    // ----------------- Fetch balance and code at pinned block -----------------
    let balance = erc20_balance_of_at(&client, &args.rpc, &args.asset, &args.target, args.block)
        .with_context(|| "fetching balance")?;
    let target_code = get_code_at(&client, &args.rpc, &args.target, args.block)?;
    let asset_code = get_code_at(&client, &args.rpc, &args.asset, args.block)?;
    let target_sha: [u8; 32] = Sha256::digest(&target_code).into();
    let asset_sha: [u8; 32] = Sha256::digest(&asset_code).into();

    // ----------------- Read calldata file -----------------
    let calldata_bytes = read_calldata(&args.calldata)?;
    if calldata_bytes.len() < 4 {
        bail!("calldata must be at least 4 bytes (needs a function selector)");
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata_bytes[0..4]);

    // ----------------- Build witness chunks -----------------
    // Compute the commitment exactly like the guest does
    let commitment = commit_all_host(&balance, &calldata_bytes, &target_code, &asset_code);

    // ----------------- Public inputs -----------------
    let asset20 = addr_to_20(&args.asset)?;
    let target20 = addr_to_20(&args.target)?;
    let threshold: u128 = args.threshold.parse().context("threshold must be decimal u128")?;

    let pubin = PublicInputs {
        threshold,
        commitment,
        asset: asset20,
        target: target20,
        selector,
        target_code_sha256: target_sha,
        asset_code_sha256: asset_sha,
    };

    // ----------------- Prove in zkVM -----------------
    let env = ExecutorEnv::builder()
        .write(&pubin)?
        .write(&balance)?
        .write(&calldata_bytes)?
        .write(&target_code)?
        .write(&asset_code)?
        .build()?;
    let prover = default_prover();
    let receipt = prover.prove_elf(env, METHOD_ELF)?;
    receipt.verify(METHOD_ID)?;

    // ----------------- Journal / output -----------------
    let journal: PublicOutputs = receipt.journal.decode()?;
    let potential_loss_hex = format!("0x{}{}", hex::encode(journal.potential_loss_hi), hex::encode(journal.potential_loss_lo));

    println!("✅ Proof verified");
    println!("• block      = {}", args.block);
    println!("• asset      = {}", &args.asset);
    println!("• target     = {}", &args.target);
    println!("• selector   = 0x{}", hex::encode(journal.selector));
    println!("• threshold  = {}", journal.threshold);
    println!("• potential_loss = {potential_loss_hex}");
    println!("• can_drain_above_thr = {}", journal.can_drain_above_threshold);

    if let Some(out) = args.out {
        fs::write(out, serde_json::to_vec_pretty(&journal)?)?;
    }
    Ok(())
}

// ----------------- Helpers -----------------


fn erc20_balance_of_at(
    client: &Client,
    rpc: &str,
    asset: &str,
    target: &str,
    block: u64,
) -> Result<[u8; 32]> {
    const SEL: &str = "70a08231"; // balanceOf(address)
    let addr = target.trim_start_matches("0x");
    let calldata = format!("0x{}{}", SEL, left_pad_32(addr)?);
    let block_hex = format!("0x{:x}", block);

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            { "to": asset, "data": calldata },
            block_hex
        ]
    });

    let res = client.post(rpc).header(CONTENT_TYPE, "application/json")
        .json(&req).send()?.error_for_status()?.json::<serde_json::Value>()?;

    let data = res["result"].as_str().ok_or_else(|| anyhow!("missing eth_call result"))?;
    let bytes = hex::decode(data.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        bail!("eth_call returned {} bytes, expected 32", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn get_code_at(client: &Client, rpc: &str, addr: &str, block: u64) -> Result<Vec<u8>> {
    let res = client.post(rpc).header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
            "params": [addr, format!("0x{:x}", block)]
        })).send()?.error_for_status()?.json::<serde_json::Value>()?;
    let hexcode = res["result"].as_str().ok_or_else(|| anyhow!("no code in result"))?;
    let bytes = hex::decode(hexcode.trim_start_matches("0x"))?;
    // EVM returns runtime bytecode; it may be empty for proxies at wrong slots; that's fine for PoC.
    // Normalize empty to empty Vec (already).
    Ok(bytes)
}

fn left_pad_32(s20: &str) -> Result<String> {
    if !s20.starts_with("0x") || s20.len() != 42 {
        bail!("address must be 0x + 40 hex chars");
    }
    Ok(format!("{:0>64}", s20.trim_start_matches("0x").to_lowercase()))
}

fn addr_to_20(a: &str) -> Result<[u8; 20]> {
    if !a.starts_with("0x") || a.len() != 42 {
        bail!("address must be 0x + 40 hex chars");
    }
    let mut out = [0u8; 20];
    let bytes = hex::decode(&a[2..])?;
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_calldata(path: &PathBuf) -> Result<Vec<u8>> {
    let raw = fs::read(path).with_context(|| format!("reading {:?}", path))?;
    // If file looks like ascii "0x....", parse as hex; else use raw bytes.
    let as_str = core::str::from_utf8(&raw).unwrap_or_default().trim();
    if as_str.starts_with("0x") && as_str.len() >= 10 && as_str.chars().all(|c| c.is_ascii_graphic()) {
        let data = hex::decode(as_str.trim_start_matches("0x"))?;
        Ok(data)
    } else {
        Ok(raw)
    }
}

// Must mirror the guest's commitment exactly.
fn commit_all_host(balance: &[u8; 32], calldata: &[u8], target_code: &[u8], asset_code: &[u8]) -> [u8; 32] {
    // sha256( "BBP" || len(balance) || balance || len(calldata) || calldata
    //                 || len(target_code)|| target_code || len(asset_code)|| asset_code )
    let mut hasher = Sha256::new();
    hasher.update(b"BBP");
    hasher.update((balance.len() as u32).to_be_bytes());
    hasher.update(balance);
    hasher.update((calldata.len() as u32).to_be_bytes());
    hasher.update(calldata);
    hasher.update((target_code.len() as u32).to_be_bytes());
    hasher.update(target_code);
    hasher.update((asset_code.len() as u32).to_be_bytes());
    hasher.update(asset_code);
    hasher.finalize().into()
}