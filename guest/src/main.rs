#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicInputs {
    pub target: [u8; 20],
    pub sender: [u8; 20],
    pub token: [u8; 20],
    pub threshold: u128,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateInputs {
    pub calldata: Vec<u8>,
    pub pre_balance: u128,
    pub post_balance: u128,
}

pub fn main() {
    let public: PublicInputs = env::read();
    let private: PrivateInputs = env::read();

    let delta = private.pre_balance.saturating_sub(private.post_balance);

    assert!(
        delta > public.threshold,
        "Token loss did not exceed threshold: {} <= {}",
        delta,
        public.threshold
    );

    env::commit(&public);
}