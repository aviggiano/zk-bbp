#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use methods::{PublicInputs, PublicOutputs};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read: public inputs, then witness chunks in this exact order.
    let pubin: PublicInputs = env::read();

    // Witness parts:
    //  (1) current balance (32 bytes big-endian u256)
    let balance: [u8; 32] = env::read();
    //  (2) calldata (opaque; we only check selector matches pub input)
    let calldata: Vec<u8> = env::read();
    //  (3) target bytecode
    let target_code: Vec<u8> = env::read();
    //  (4) asset bytecode
    let asset_code: Vec<u8> = env::read();

    // ---- Recompute the overall commitment over length-tagged blobs ----
    let commitment = commit_all(&balance, &calldata, &target_code, &asset_code);
    assert_eq!(commitment, pubin.commitment, "commitment mismatch");

    // ---- Sanity checks on calldata & code digests (bind PoC to actual code) ----
    // Calldata must be at least 4 bytes for selector
    assert!(calldata.len() >= 4, "calldata too short");
    assert_eq!(&calldata[0..4], &pubin.selector, "selector mismatch");

    // SHA-256 of code blobs must match public digests
    let t_sha = sha::digest(&target_code);
    let a_sha = sha::digest(&asset_code);
    assert_eq!(t_sha.as_bytes(), &pubin.target_code_sha256, "target code digest mismatch");
    assert_eq!(a_sha.as_bytes(), &pubin.asset_code_sha256, "asset code digest mismatch");

    // ---- Check if exploit can drain above threshold ----
    // For simplicity, assume the calldata can drain the entire balance
    // In a real implementation, you would simulate the calldata execution
    let potential_loss = balance;  // Assume full balance is drainable
    let can_drain = ge_u256_vs_u128(&potential_loss, pubin.threshold);

    // ---- Commit outputs ----
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&potential_loss[0..16]);
    lo.copy_from_slice(&potential_loss[16..32]);

    let out = PublicOutputs {
        threshold: pubin.threshold,
        potential_loss_hi: hi,
        potential_loss_lo: lo,
        can_drain_above_threshold: can_drain,
        selector: pubin.selector,
        asset: pubin.asset,
        target: pubin.target,
    };
    env::commit(&out);
}

// Compute: sha256( "BBP" || len(balance) || balance || len(calldata) || calldata
//                     || len(target_code) || target_code || len(asset_code) || asset_code )
fn commit_all(balance: &[u8; 32], calldata: &[u8], target_code: &[u8], asset_code: &[u8]) -> [u8; 32] {
    use alloc::vec;
    let mut data = vec![];
    data.extend_from_slice(b"BBP");
    data.extend_from_slice(&(balance.len() as u32).to_be_bytes());
    data.extend_from_slice(balance);
    data.extend_from_slice(&(calldata.len() as u32).to_be_bytes());
    data.extend_from_slice(calldata);
    data.extend_from_slice(&(target_code.len() as u32).to_be_bytes());
    data.extend_from_slice(target_code);
    data.extend_from_slice(&(asset_code.len() as u32).to_be_bytes());
    data.extend_from_slice(asset_code);
    *sha::digest(&data).as_bytes()
}

// ---------- helpers (big-endian arithmetic) ----------

fn ge_u256_vs_u128(a: &[u8; 32], thr: u128) -> bool {
    for b in &a[0..16] {
        if *b != 0 { return true; }
    }
    let mut lo_bytes = [0u8; 16];
    lo_bytes.copy_from_slice(&a[16..32]);
    let lo = u128::from_be_bytes(lo_bytes);
    lo >= thr
}