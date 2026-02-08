/// 高级哈希操作模块
///
/// 该模块提供基于 SHA-256 的高级哈希功能，包括双 SHA-256、哈希组合和 Merkle 树操作。

#[allow(dead_code)]
use crate::crypto::sha256::Sha256Riscv;

/// 计算双 SHA-256 哈希
///
/// 对数据连续应用两次 SHA-256 哈希。
/// 用于比特币等区块链系统的交易哈希。
/// 双哈希可以防止长度扩展攻击。
///
/// # 参数
///
/// * `data` - 要哈希的数据
///
/// # 返回
///
/// 32 字节双哈希结果
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256Riscv::hash(data);
    Sha256Riscv::hash(&first)
}

/// 合并两个哈希值
///
/// 将两个 32 字节哈希值合并为一个新的哈希值。
/// 常用于构建哈希树或组合多个哈希。
///
/// # 参数
///
/// * `a` - 第一个哈希值（32 字节）
/// * `b` - 第二个哈希值（32 字节）
///
/// # 返回
///
/// 合并后的 32 字节哈希值
pub fn hash_combine(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(a);
    combined[32..].copy_from_slice(b);
    double_sha256(&combined)
}

/// 创建 Merkle 树叶子节点
///
/// 将数据转换为 Merkle 树的叶子节点。
/// 叶子节点通过前缀 0x00 标识，然后进行双 SHA-256 哈希。
///
/// # 参数
///
/// * `data` - 原始数据，将被哈希后作为叶子
///
/// # 返回
///
/// Merkle 叶子节点的 32 字节哈希
pub fn merkle_leaf(data: &[u8]) -> [u8; 32] {
    let mut prefixed = Vec::with_capacity(data.len() + 1);
    prefixed.push(0x00);
    prefixed.extend_from_slice(data);
    double_sha256(&prefixed)
}

/// 创建 Merkle 树分支节点
///
/// 计算两个子节点的父节点哈希。
/// 分支节点通过前缀 0x01 标识，然后进行双 SHA-256 哈希。
///
/// # 参数
///
/// * `left` - 左子节点哈希（32 字节）
/// * `right` - 右子节点哈希（32 字节）
///
/// # 返回
///
/// 父节点的 32 字节哈希
pub fn merkle_branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 65];
    combined[0] = 0x01;
    combined[1..33].copy_from_slice(left);
    combined[33..65].copy_from_slice(right);
    double_sha256(&combined)
}

/// 计算 Merkle 树的根哈希
///
/// 从一组叶子节点递归计算 Merkle 根。
/// 如果叶子数为奇数，最后一个节点会重复使用。
///
/// # 参数
///
/// * `leaves` - Merkle 树的叶子节点数组，每个为 32 字节哈希
///
/// # 返回
///
/// Merkle 根的 32 字节哈希
///
/// # 算法
///
/// 1. 如果只有一片叶子，返回该叶子
/// 2. 否则成对计算每层的分支哈希
/// 3. 重复直到只剩一个哈希，即为根
pub fn calculate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(merkle_branch(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0]);
            }
        }

        level = next_level;
    }

    level[0]
}
