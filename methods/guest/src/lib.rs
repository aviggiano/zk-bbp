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