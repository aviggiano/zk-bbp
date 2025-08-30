#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use risc0_zkvm::sha;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub threshold: u128,
    pub commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicOutputs {
    pub threshold: u128,
    pub loss_hi: [u8; 16],
    pub loss_lo: [u8; 16],
    pub loss_ge_threshold: bool,
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read public inputs and private witness.
    let pubin: PublicInputs = env::read();
    // Witness blob is 64 bytes: pre_balance (32B big-endian) || post_balance (32B big-endian)
    let witness: [u8; 64] = env::read();

    // 1) Recompute commitment = sha256(witness)
    let digest = sha::sha256(&witness);
    assert_eq!(digest.as_bytes(), &pubin.commitment, "bad commitment");

    // 2) Parse pre/post as big-endian 32-byte unsigned ints
    let mut pre = [0u8; 32];
    let mut post = [0u8; 32];
    pre.copy_from_slice(&witness[0..32]);
    post.copy_from_slice(&witness[32..64]);

    // 3) loss = max(pre - post, 0)
    let loss = sub_u256_be_saturating(&pre, &post);

    // 4) Check loss >= threshold (u128)
    let ge = ge_u256_vs_u128(&loss, pubin.threshold);

    // 5) Commit public outputs
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&loss[0..16]);
    lo.copy_from_slice(&loss[16..32]);

    let out = PublicOutputs {
        threshold: pubin.threshold,
        loss_hi: hi,
        loss_lo: lo,
        loss_ge_threshold: ge,
    };
    env::commit(&out);
}

// ---------- helpers (big-endian arithmetic) ----------

fn sub_u256_be_saturating(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Compute a - b with borrow; if underflow, return 0.
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let av = a[i] as u16;
        let bv = b[i] as u16;
        let mut diff = av.wrapping_sub(bv + borrow);
        if av < bv + borrow {
            borrow = 1;
            diff = diff.wrapping_add(1 << 8); // borrow from next byte
        } else {
            borrow = 0;
        }
        out[i] = (diff & 0xff) as u8;
    }
    if borrow != 0 {
        // underflow => saturate to zero
        [0u8; 32]
    } else {
        out
    }
}

fn ge_u256_vs_u128(a: &[u8; 32], thr: u128) -> bool {
    // If high 128 bits are non-zero, a >= 2^128 > thr (unless thr == max u128); treat as true.
    let mut hi_nonzero = false;
    for b in &a[0..16] {
        if *b != 0 {
            hi_nonzero = true;
            break;
        }
    }
    if hi_nonzero {
        return true;
    }
    // Compare low 128 bits (big-endian) to thr
    let mut lo_bytes = [0u8; 16];
    lo_bytes.copy_from_slice(&a[16..32]);
    let lo = u128::from_be_bytes(lo_bytes);
    lo >= thr
}