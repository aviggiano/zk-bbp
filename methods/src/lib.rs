use serde::{Deserialize, Serialize};

/// Public inputs the guest receives (committed on-chain in a full system).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub threshold: u128,        // payout threshold
    pub commitment: [u8; 32],   // sha256(witness_blob)
}

/// Public outputs the guest commits to the journal.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicOutputs {
    pub threshold: u128,
    pub loss_hi: [u8; 16],   // high 128 bits of (pre - post)
    pub loss_lo: [u8; 16],   // low  128 bits  of (pre - post)
    pub loss_ge_threshold: bool,
}

// Guest module to make the methods visible
pub mod guest {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}