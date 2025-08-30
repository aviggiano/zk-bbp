use risc0_zkvm::{default_prover, ExecutorEnv};
use zk_bug_bounty_methods::GUEST_ELF;
use guest::{PublicInputs, PrivateInputs};

fn main() {
    let public_inputs = PublicInputs {
        target: [0xaa; 20],
        sender: [0xbb; 20],
        token: [0xcc; 20],
        threshold: 1000,
    };

    let private_inputs = PrivateInputs {
        calldata: vec![0xde, 0xad, 0xbe, 0xef],
        pre_balance: 5000,
        post_balance: 3000,
    };

    let env = ExecutorEnv::builder()
        .write(&public_inputs)
        .unwrap()
        .write(&private_inputs)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let receipt = prover.prove(env, GUEST_ELF).unwrap();

    receipt.verify(zk_bug_bounty_methods::GUEST_ID).unwrap();

    println!("ZK proof succeeded!");
    println!("Public inputs: {:?}", public_inputs);
    println!("Balance delta: {}", private_inputs.pre_balance - private_inputs.post_balance);
}