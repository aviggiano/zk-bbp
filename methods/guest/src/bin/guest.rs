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
    //  (1) pre||post (64 bytes big-endian u256s)
    let pre_post: [u8; 64] = env::read();
    //  (2) calldata (opaque; we only check selector matches pub input)
    let calldata: Vec<u8> = env::read();
    //  (3) target bytecode
    let target_code: Vec<u8> = env::read();
    //  (4) asset bytecode
    let asset_code: Vec<u8> = env::read();

    // ---- Recompute the overall commitment over length-tagged blobs ----
    let commitment = commit_all(&pre_post, &calldata, &target_code, &asset_code);
    assert_eq!(commitment, pubin.commitment, "commitment mismatch");

    // ---- Sanity checks on calldata & code digests (bind PoC to actual code) ----
    // Calldata must be at least 4 bytes for selector
    assert!(calldata.len() >= 4, "calldata too short");
    assert_eq!(&calldata[0..4], &pubin.selector, "selector mismatch");

    // SHA-256 of code blobs must match public digests
    let t_sha = sha::sha256(&target_code);
    let a_sha = sha::sha256(&asset_code);
    assert_eq!(t_sha.as_bytes(), &pubin.target_code_sha256, "target code digest mismatch");
    assert_eq!(a_sha.as_bytes(), &pubin.asset_code_sha256, "asset code digest mismatch");

    // ---- Parse balances & check threshold ----
    let mut pre = [0u8; 32];
    let mut post = [0u8; 32];
    pre.copy_from_slice(&pre_post[0..32]);
    post.copy_from_slice(&pre_post[32..64]);

    let loss = sub_u256_be_saturating(&pre, &post);
    let ge = ge_u256_vs_u128(&loss, pubin.threshold);

    // ---- Commit outputs ----
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&loss[0..16]);
    lo.copy_from_slice(&loss[16..32]);

    let out = PublicOutputs {
        threshold: pubin.threshold,
        loss_hi: hi,
        loss_lo: lo,
        loss_ge_threshold: ge,
        selector: pubin.selector,
        asset: pubin.asset,
        target: pubin.target,
    };
    env::commit(&out);
}

// Compute: sha256( "BBP" || len(pre_post) || pre_post || len(calldata) || calldata
//                     || len(target_code) || target_code || len(asset_code) || asset_code )
fn commit_all(pre_post: &[u8; 64], calldata: &[u8], target_code: &[u8], asset_code: &[u8]) -> [u8; 32] {
    let mut st = sha::Impl::new();
    st.update(b"BBP");
    write_len(&mut st, pre_post.len() as u32);
    st.update(pre_post);
    write_len(&mut st, calldata.len() as u32);
    st.update(calldata);
    write_len(&mut st, target_code.len() as u32);
    st.update(target_code);
    write_len(&mut st, asset_code.len() as u32);
    st.update(asset_code);
    *st.finalize().as_bytes()
}

fn write_len(st: &mut sha::Impl, n: u32) {
    let be = n.to_be_bytes();
    st.update(&be);
}

// ---------- helpers (big-endian arithmetic) ----------

fn sub_u256_be_saturating(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let av = a[i] as u16;
        let bv = b[i] as u16;
        let mut diff = av.wrapping_sub(bv + borrow);
        if av < bv + borrow {
            borrow = 1;
            diff = diff.wrapping_add(1 << 8);
        } else {
            borrow = 0;
        }
        out[i] = (diff & 0xff) as u8;
    }
    if borrow != 0 { [0u8; 32] } else { out }
}

fn ge_u256_vs_u128(a: &[u8; 32], thr: u128) -> bool {
    for b in &a[0..16] {
        if *b != 0 { return true; }
    }
    let mut lo_bytes = [0u8; 16];
    lo_bytes.copy_from_slice(&a[16..32]);
    let lo = u128::from_be_bytes(lo_bytes);
    lo >= thr
}