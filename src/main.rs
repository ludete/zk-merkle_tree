use halo2_proofs::dev::MockProver;
use merkle_proof::merkle_tree::{
    merkle_circuit,
    merkle_tree::{MerkelTree, MerkleProof, N_LEAFS, N_ROOT_ROW},
};

fn main() {
    let tree = MerkelTree::rand_generate();
    let chanllenge_leaf: usize = thread_rng().gen_range(0..N_LEAFS);

    let k = (N_ROOT_ROW as f32).log2().ceil() as u32;
    let mut pub_inputs = vec![tree.root()];

    let proof = tree.gen_proof(chanllenge_leaf);
    let tree_circuit = merkle_circuit::MerkleCircuit {
        leaf: Some(proof.value),
        merkle_path: Some(proof.siblings),
        merkle_path_index: Some(proof.siblings_index),
    };
    let prover = MockProver::run(k, &tree_circuit, pub_inputs)?;
    assert!(prover.verify().is_ok())
}
