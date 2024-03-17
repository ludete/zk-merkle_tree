use std::usize;

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

use crate::merkle_tree::{
    hash::{PoseidonChip, PoseidonConfig, PoseidonSpec},
    merkle_tree::{self, PATH_LEN},
};

#[derive(Clone, Debug)]
struct MerkleChipConfig<const N_LEAF: usize> {
    // x行 存储proof的叶子结点
    // x+1行 存储merkle树的左子结点
    a_col: Column<Advice>,
    // x行 存储merkle path中的其它结点
    // x+1行 存储merkle树的右子结点
    b_col: Column<Advice>,
    // x行 存储merkle path结点的索引，标识为树的左/右结点
    // 0:左结点，1：右结点
    // x+1行 存储证明过程中计算的 中间节点hash
    c_col: Column<Advice>,
    // 存储merkle root，校验计算过程的正确性
    pub_col: Column<Instance>,

    // 是否启用pub约束
    s_pub: Selector,
    // 标识需要对两个叶子结点排序
    s_swap: Selector,
    // 当c列存储的数据为merkle path节点索引时，enable
    s_bool: Selector,
    // 标识非页子结点的哈希
    s_hash: Selector,

    poseidon_middle_config: PoseidonConfig<2, 1, N_LEAF>,
}

struct MerkleChip<const N_LEAF: usize> {
    config: MerkleChipConfig<N_LEAF>,
}

impl<const N_LEAF: usize> Chip<Fp> for MerkleChip<N_LEAF> {
    type Config = MerkleChipConfig<N_LEAF>;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

struct Alloc {
    cell: AssignedCell<Fp, Fp>,
    value: Fp,
}

enum MaybeAlloc {
    Alloc(Alloc),
    Unalloc(Fp),
}

impl MaybeAlloc {
    fn value(&self) -> Fp {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.value.clone(),
            MaybeAlloc::Unalloc(alloc) => alloc.clone(),
        }
    }

    fn cell(&self) -> AssignedCell<Fp, Fp> {
        match self {
            MaybeAlloc::Alloc(alloc) => alloc.cell.clone(),
            MaybeAlloc::Unalloc(_) => unreachable!(),
        }
    }
}

impl<const N_LEAF: usize> MerkleChip<N_LEAF> {
    pub fn new(config: MerkleChipConfig<N_LEAF>) -> Self {
        MerkleChip { config }
    }

    pub fn confignure(cs: &mut ConstraintSystem<Fp>) -> MerkleChipConfig<N_LEAF> {
        // columns
        let a_col = cs.advice_column();
        let b_col = cs.advice_column();
        let c_col = cs.advice_column();
        let pub_col = cs.instance_column();

        // selector
        let s_pub = cs.selector();
        let s_swap = cs.selector();
        let s_bool = cs.selector();
        let s_hash = cs.selector();

        // Poseidon
        // we need 2 * WIDTH fixed columns for poseidon config + 1 for the range check chip
        let fixed_columns: [Column<Fixed>; 5] = std::array::from_fn(|_| cs.fixed_column());
        let poseidon_middle_config = PoseidonChip::<PoseidonSpec, 2, 1, { N_LEAF + 2 }>::configure(
            cs,
            [a_col, b_col],
            c_col,
            fixed_columns[0..2].try_into().unwrap(),
            fixed_columns[2..].try_into().unwrap(),
        );

        cs.enable_equality(a_col);
        cs.enable_equality(b_col);

        // pub selector enable后，pub_col = c_col
        cs.create_gate("public constraint for input", |cs| {
            let c = cs.query_advice(c_col, Rotation::cur());
            let pc = cs.query_instance(pub_col, Rotation::cur());
            let ps = cs.query_selector(s_pub);
            ps * (c - pc)
        });

        // proof merkle path的节点用0/1标识
        // 0：标识左节点，1: 标识右结点
        cs.create_gate("merkle path index", |cs| {
            let c = cs.query_advice(c_col, Rotation::cur());
            let sb = cs.query_selector(s_bool);
            sb * (Expression::Constant(Fp::one()) - c) * c
        });

        // a,b 节点依据merkle path的索引进行互换，保证x+1行a、b两列数据按照左、右节点排序
        cs.create_gate("swap nodes to corret right/left in tree", |cs| {
            let a = cs.query_advice(a_col, Rotation::cur());
            let b = cs.query_advice(b_col, Rotation::cur());
            let index = cs.query_advice(c_col, Rotation::cur());
            let s_swap = cs.query_selector(s_swap);
            let left = cs.query_advice(a_col, Rotation::next());
            let right = cs.query_advice(b_col, Rotation::next());
            s_swap * (index * Fp::from(2) * (b.clone() - a.clone())) - (left - a) - (b - right)
        });

        cs.create_gate("hash", |cs| {
            let left = cs.query_advice(a_col, Rotation::next());
            let right = cs.query_advice(b_col, Rotation::next());
            let hash = cs.query_advice(c_col, Rotation::next());
            let s_hash = cs.query_selector(s_hash);
            s_hash * (left * right - hash)
        });

        MerkleChipConfig {
            a_col,
            b_col,
            c_col,
            pub_col,
            s_bool,
            s_hash,
            s_pub,
            s_swap,
            poseidon_middle_config,
        }
    }

    fn synthesis(
        &self,
        layouter: &mut impl Layouter<Fp>,
        leaf: Option<Fp>,
        merkle_path: Option<Vec<Fp>>,
        merkle_path_index: Option<Vec<Fp>>,
    ) -> Result<(), Error> {
        let mut digest = self.hash_leaf_layer(
            layouter,
            leaf,
            merkle_path.unwrap()[0],
            merkle_path_index.unwrap()[0],
        )?;
        for layer in 1..merkle_tree::PATH_LEN {
            digest = self.hash_non_leaf_layer(
                layouter,
                digest,
                merkle_path.unwrap()[layer],
                merkle_path_index.unwrap()[layer],
                layer,
            )?;
        }
        Ok(())
    }

    fn hash_leaf_layer(
        &self,
        layouter: &mut impl Layouter<Fp>,
        leaf: Option<Fp>,
        path_elem: Fp,
        c_bit: Fp,
    ) -> Result<Alloc, Error> {
        self.hash_layer_nodes(
            layouter,
            MaybeAlloc::Unalloc(leaf.unwrap()),
            path_elem,
            c_bit,
            0,
        )
    }

    fn hash_non_leaf_layer(
        &self,
        layouter: &mut impl Layouter<Fp>,
        digest: Alloc,
        path_elem: Fp,
        c_bit: Fp,
        layer: usize,
    ) -> Result<Alloc, Error> {
        self.hash_layer_nodes(layouter, MaybeAlloc::Alloc(digest), path_elem, c_bit, layer)
    }

    // 1. 依据输入的节点填充表格至表格x行
    // 2. 依据c_bit 区分输入节点的左/右顺序，并填入x+1行
    // 3. 使用x+1行的左、右节点计算中间节点的哈希值，并写入x+1行的c列
    // 正确填写表格的数据，并在对应环节启用selector，满足configure中对表格的约束
    fn hash_layer_nodes(
        &self,
        layouter: &mut impl Layouter<Fp>,
        leaf_or_digest: MaybeAlloc,
        path_elem: Fp,
        c_bit: Fp,
        layer: usize,
    ) -> Result<Alloc, Error> {
        let mut digest_alloc: Option<Alloc> = None;
        layouter.assign_region(
            || "leaf layer",
            |mut region| {
                let mut row = 0;
                let a_value = leaf_or_digest.value();

                // 对row行的a、b、c列按写入顺序填入两个节点以及对应的index
                let a_cell = region.assign_advice(
                    || {
                        format!(
                            "{} in layer {}",
                            if layer == 0 { "leaf" } else { "inner node" },
                            layer
                        )
                    },
                    self.config.a_col,
                    row,
                    || Value::known(a_value),
                )?;
                let b_cell = region.assign_advice(
                    || format!("merkle path element layer: {}", layer),
                    self.config.b_col,
                    row,
                    || Value::known(path_elem),
                )?;

                let c_cell = region.assign_advice(
                    || format!("merkle path element index {}", layer),
                    self.config.c_col,
                    row,
                    || Value::known(c_bit),
                )?;

                // 非叶子结点，leaf_or_digest 为witness计算过程的中间节点哈希
                if layer > 0 {
                    let prev_cell = leaf_or_digest.cell();
                    // copy约束，非叶子层时，a列的数据与上次witness计算过程中的hash相等
                    region.constrain_equal(prev_cell.cell(), a_cell.cell())?;
                }

                self.config.s_bool.enable(&mut region, row)?;
                self.config.s_swap.enable(&mut region, row)?;

                let (left_val, right_val) = if c_bit == Fp::zero() {
                    (a_value, path_elem)
                } else {
                    (path_elem, a_value)
                };

                row += 1;

                let left_cell = region.assign_advice(
                    || format!("left node, layer {}", layer),
                    self.config.a_col,
                    row,
                    || Value::known(left_val),
                )?;
                let right_cell = region.assign_advice(
                    || format!("right node, layer {}", layer),
                    self.config.b_col,
                    row,
                    || Value::known(right_val),
                )?;

                let poseidon_middle_chip =
                    PoseidonChip::<PoseidonSpec, 2, 1, { N_LEAF + 2 }>::construct(
                        self.config.poseidon_middle_config,
                    );
                let computed_sibling_hash =
                    poseidon_middle_chip.hash(layouter, [left_cell, right_cell])?;

                let digest = region.assign_advice(
                    || format!("hash node, layer {}", layer),
                    self.config.c_col,
                    row,
                    || Value::known(computed_sibling_hash.value()),
                )?;

                self.config.s_hash.enable(&mut region, row);
                if layer == PATH_LEN - 1 {
                    self.config.s_pub.enable(&mut region, row);
                }
                Ok(())
            },
        );

        Ok(digest_alloc.unwrap())
    }
}

#[derive(Clone, Default)]
pub struct MerkleCircuit {
    pub leaf: Option<Fp>,
    pub merkle_path: Option<Vec<Fp>>,
    pub merkle_path_index: Option<Vec<Fp>>,
}

impl Circuit<Fp> for MerkleCircuit {
    type Config = MerkleChipConfig;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(cs: &mut ConstraintSystem<Fp>) -> Self::Config {
        MerkleChip::confignure(cs)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let merkle_chip = MerkleChip::new(config);
        merkle_chip.synthesis(
            layouter,
            self.leaf,
            self.merkle_path,
            self.merkle_path_index,
        )
    }
}
