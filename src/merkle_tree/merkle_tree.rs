use std::fmt::Error;

// use eth_types::Field;
// use halo2_proofs::Field;
use crate::merkle_tree::hash;
use rand::{thread_rng, Rng};

// Merkle树包含的叶子数量，必须是2**n
pub const N_LEAFS: usize = 8;
// 证明叶子结点的merkel path路径结点数量
pub const PATH_LEN: usize = N_LEAFS.trailing_zeros() as usize;
// Merkle树的高度
pub const TREE_LEVELS: usize = PATH_LEN + 1;

// halo2约束表格中使用电路的行数
pub const N_ROWS_USED: usize = PATH_LEN * 2;
// 存储Merkle root的电路行号
pub const N_ROOT_ROW: usize = N_ROWS_USED - 1;

#[derive(Default)]
pub struct MerkleProof {
    leaf_index: usize,
    pub value: u32,
    pub siblings: Vec<u32>,
    pub siblings_index: Vec<u32>,
    pub root: u32,
}

// MerkleTree 由一个二维数组构成
pub struct MerkelTree(Vec<Vec<u32>>);

impl MerkelTree {
    pub fn rand_generate() -> Self {
        // 生成随机数种子
        let mut rng = thread_rng();

        let leafs: Vec<u32> = (0..N_LEAFS).map(|_| rng.gen::<u32>()).collect();
        let mut tree = MerkelTree(vec![leafs]);
        for l in 1..TREE_LEVELS {
            let layer = tree.0[l - 1]
                .chunks(2)
                .map(|pair| hash::mockhash(pair[0], pair[1]))
                .collect();
            tree.0.push(layer);
        }
        assert_eq!(tree.0.last().unwrap().len(), 1);
        tree
    }

    pub fn root(&self) -> u32 {
        self.0.last().unwrap()[0]
    }

    fn leafs(&self) -> Vec<u32> {
        self.0.first().unwrap().to_vec()
    }

    pub fn leaf(&self, index: usize) -> Option<u32> {
        self.0.first().unwrap().get(index).cloned()
    }
    pub fn gen_proof(&self, index: usize) -> MerkleProof {
        let path = self.get_merkle_path(index);
        let mut proof = MerkleProof {
            leaf_index: index,
            value: self.0.first().unwrap()[index],
            root: self.root(),
            siblings: vec![],
            siblings_index: vec![],
        };
        for (sib, idx) in path.iter() {
            proof.siblings.push(sib.clone());
            proof.siblings_index.push(idx.clone());
        }
        proof
    }

    fn get_merkle_path(&self, index: usize) -> Vec<(u32, u32)> {
        let mut path = vec![];
        let mut node_index = index;
        for layer in 0..PATH_LEN {
            let (sib, idx) = if node_index & 1 == 0 {
                (self.0[layer][node_index + 1].clone(), 1)
            } else {
                (self.0[layer][node_index].clone(), 0)
            };
            path.push((sib, idx));
            node_index /= 2;
        }
        path
    }

    pub fn insert_leaf(index: usize, leaf: u32) -> Result<(), Error> {
        todo!()
    }
}
