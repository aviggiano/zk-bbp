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

    /// Either explicit pre/post blocks (decimal)...
    #[arg(long)]
    block_pre: Option<u64>,
    #[arg(long)]
    block_post: Option<u64>,
    /// ...or derive them from a tx (pre = block-1, post = block)
    #[arg(long)]
    tx: Option<String>,

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

    // ----------------- Resolve blocks -----------------
    let (pre_block, post_block) = if let Some(tx) = args.tx.as_ref() {
        let block = get_tx_block_number(&client, &args.rpc, tx)?;
        if block == 0 { bail!("tx in block 0; cannot set pre = -1"); }
        (block - 1, block)
    } else {
        let pre = args.block_pre.ok_or_else(|| anyhow!("--block-pre required (or use --tx)"))?;
        let post = args.block_post.ok_or_else(|| anyhow!("--block-post required (or use --tx)"))?;
        (pre, post)
    };

    // ----------------- Fetch balances at pre/post -----------------
    let pre_balance = erc20_balance_of_at(&client, &args.rpc, &args.asset, &args.target, pre_block)
        .with_context(|| "fetching pre balance")?;
    let post_balance = erc20_balance_of_at(&client, &args.rpc, &args.asset, &args.target, post_block)
        .with_context(|| "fetching post balance")?;

    // ----------------- Fetch code at pre-block -----------------
    let target_code = get_code_at(&client, &args.rpc, &args.target, pre_block)?;
    let asset_code = get_code_at(&client, &args.rpc, &args.asset, pre_block)?;
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
    let mut pre_post = [0u8; 64];
    pre_post[0..32].copy_from_slice(&pre_balance);
    pre_post[32..64].copy_from_slice(&post_balance);

    // Compute the commitment exactly like the guest does
    let commitment = commit_all_host(&pre_post, &calldata_bytes, &target_code, &asset_code);

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
        .write(&pre_post)?
        .write(&calldata_bytes)?
        .write(&target_code)?
        .write(&asset_code)?
        .build()?;
    let prover = default_prover();
    let receipt = prover.prove_elf(env, METHOD_ELF)?;
    receipt.verify(METHOD_ID)?;

    // ----------------- Journal / output -----------------
    let journal: PublicOutputs = receipt.journal.decode()?;
    let loss_hex = format!("0x{}{}", hex::encode(journal.loss_hi), hex::encode(journal.loss_lo));

    println!("✅ Proof verified");
    println!("• pre_block  = {pre_block}");
    println!("• post_block = {post_block}");
    println!("• asset      = {}", &args.asset);
    println!("• target     = {}", &args.target);
    println!("• selector   = 0x{}", hex::encode(journal.selector));
    println!("• threshold  = {}", journal.threshold);
    println!("• loss       = {loss_hex}");
    println!("• loss ≥ thr = {}", journal.loss_ge_threshold);

    if let Some(out) = args.out {
        fs::write(out, serde_json::to_vec_pretty(&journal)?)?;
    }
    Ok(())
}

// ----------------- Helpers -----------------

fn get_tx_block_number(client: &Client, rpc: &str, tx_hash: &str) -> Result<u64> {
    let res = client
        .post(rpc)
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash]
        }))
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;

    let hexnum = res["result"]["blockNumber"]
        .as_str().ok_or_else(|| anyhow!("no blockNumber in receipt"))?;
    Ok(u64::from_str_radix(hexnum.trim_start_matches("0x"), 16)?)
}

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
fn commit_all_host(pre_post: &[u8; 64], calldata: &[u8], target_code: &[u8], asset_code: &[u8]) -> [u8; 32] {
    // sha256( "BBP" || len(pre_post) || pre_post || len(calldata) || calldata
    //                 || len(target_code)|| target_code || len(asset_code)|| asset_code )
    let mut hasher = Sha256::new();
    hasher.update(b"BBP");
    hasher.update((pre_post.len() as u32).to_be_bytes());
    hasher.update(pre_post);
    hasher.update((calldata.len() as u32).to_be_bytes());
    hasher.update(calldata);
    hasher.update((target_code.len() as u32).to_be_bytes());
    hasher.update(target_code);
    hasher.update((asset_code.len() as u32).to_be_bytes());
    hasher.update(asset_code);
    hasher.finalize().into()
}