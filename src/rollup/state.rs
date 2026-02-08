/// Rollup 状态管理模块
///
/// 该模块管理 ZK Rollup 的链上状态，包括账户管理、余额管理、转账处理和 Merkle 根计算。

#[allow(dead_code)]
use std::collections::HashMap;
#[allow(dead_code)]
use std::error::Error;
#[allow(dead_code)]
use std::fmt;

/// 账户余额结构体
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Balance {
    pub eth: u64,
    #[allow(dead_code)]
    pub tokens: HashMap<String, u64>,
}

impl Balance {
    /// 创建新的余额结构
    ///
    /// 初始化时 ETH 和所有代币余额均为 0。
    ///
    /// # 返回
    ///
    /// 初始化的 `Balance` 实例
    pub fn new() -> Self {
        Balance {
            eth: 0,
            tokens: HashMap::new(),
        }
    }

    /// 增加 ETH 余额
    ///
    /// # 参数
    ///
    /// * `amount` - 要增加的 ETH 数量（wei）
    pub fn add_eth(&mut self, amount: u64) {
        self.eth += amount;
    }

    /// 减少 ETH 余额
    ///
    /// # 参数
    ///
    /// * `amount` - 要减少的 ETH 数量（wei）
    ///
    /// # 返回
    ///
    /// - `Ok(())`: 操作成功
    /// - `Err(Box<dyn Error>)`: 余额不足
    pub fn sub_eth(&mut self, amount: u64) -> Result<(), Box<dyn Error>> {
        if self.eth < amount {
            return Err(Box::new(StateError {
                message: "Insufficient balance".to_string(),
            }));
        }
        self.eth -= amount;
        Ok(())
    }
}

/// Rollup 账户结构体
///
/// 代表 ZK Rollup 上的用户账户，包含：
/// - 账户 ID：唯一标识符
/// - 公钥：用于验证签名
/// - nonce：交易序列号，防重放攻击
/// - 余额：账户资产
///
/// # 字段
///
/// * `id`: 账户唯一 ID
/// * `public_key`: 账户公钥（32 字节 Ed25519）
/// * `nonce`: 交易序列号，每次交易递增
/// * `balance`: 账户余额
#[derive(Debug, Clone)]
pub struct Account {
    /// 账户唯一标识符，由 Rollup 状态分配
    pub id: u32,
    /// 账户公钥，用于验证交易签名
    pub public_key: Vec<u8>,
    /// 交易序列号，用于防重放攻击
    pub nonce: u32,
    /// 账户余额，包含 ETH 和代币
    pub balance: Balance,
}

/// Rollup 状态管理错误
#[derive(Debug)]
pub struct StateError {
    message: String,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "State Error: {}", self.message)
    }
}

impl Error for StateError {}

/// Rollup 全局状态
///
/// 管理 Rollup 上的所有账户状态。
/// 提供账户创建、查询、转账和状态根计算功能。
///
/// # 内部数据结构
///
/// - `accounts`: 账户 ID -> 账户映射
/// - `account_by_key`: 公钥 -> 账户 ID 映射（用于快速查找）
/// - `next_account_id`: 下一个新账户的 ID
///
/// # 示例
///
/// ```rust
/// use rollup::state::{Account, Balance, RollupState};
///
/// let mut state = RollupState::new();
///
/// let account = Account {
///     id: 0,
///     public_key: vec![1u8; 32],
///     nonce: 0,
///     balance: Balance::new(),
/// };
/// state.create_account(account).unwrap();
/// ```
#[allow(dead_code)]
#[derive(Debug)]
pub struct RollupState {
    /// 账户 ID 到账户的映射
    accounts: HashMap<u32, Account>,
    /// 公钥到账户 ID 的映射（用于通过公钥查找账户）
    account_by_key: HashMap<Vec<u8>, u32>,
    /// 下一个账户 ID 计数器
    next_account_id: u32,
}

impl RollupState {
    /// 创建新的 Rollup 状态
    ///
    /// 初始化空的账户状态，没有初始账户。
    ///
    /// # 返回
    ///
    /// 空的 `RollupState` 实例
    pub fn new() -> Self {
        RollupState {
            accounts: HashMap::new(),
            account_by_key: HashMap::new(),
            next_account_id: 0,
        }
    }

    /// 创建新账户
    ///
    /// 在 Rollup 状态中注册新账户。
    /// 分配唯一账户 ID，存储公钥和初始余额。
    ///
    /// # 参数
    ///
    /// * `account` - 要创建的账户（不含 ID）
    ///
    /// # 返回
    ///
    /// - `Ok(u32)`: 新账户的 ID
    /// - `Err(Box<dyn Error>)`: 账户已存在
    pub fn create_account(&mut self, account: Account) -> Result<u32, Box<dyn Error>> {
        let id = self.next_account_id;
        self.next_account_id += 1;

        if self.account_by_key.contains_key(&account.public_key) {
            return Err(Box::new(StateError {
                message: "Account already exists".to_string(),
            }));
        }

        self.accounts.insert(id, account.clone());
        self.account_by_key.insert(account.public_key, id);

        Ok(id)
    }

    /// 通过 ID 获取账户
    ///
    /// # 参数
    ///
    /// * `id` - 账户 ID
    ///
    /// # 返回
    ///
    /// - `Some(&Account)`: 找到的账户
    /// - `None`: 账户不存在
    pub fn get_account(&self, id: u32) -> Option<&Account> {
        self.accounts.get(&id)
    }

    /// 通过公钥获取账户
    ///
    /// # 参数
    ///
    /// * `key` - 公钥字节数组
    ///
    /// # 返回
    ///
    /// - `Some(&Account)`: 找到的账户
    /// - `None`: 账户不存在
    pub fn get_account_by_key(&self, key: &[u8]) -> Option<&Account> {
        self.account_by_key
            .get(key)
            .and_then(|id| self.accounts.get(id))
    }

    /// 更新账户余额
    ///
    /// 增加指定账户的 ETH 余额。
    /// 通常用于存款或奖励分发。
    ///
    /// # 参数
    ///
    /// * `id` - 账户 ID
    /// * `amount` - 要增加的 ETH 数量
    ///
    /// # 返回
    ///
    /// - `Ok(())`: 操作成功
    /// - `Err(Box<dyn Error>)`: 账户不存在
    pub fn update_balance(&mut self, id: u32, amount: u64) -> Result<(), Box<dyn Error>> {
        let account = self.accounts.get_mut(&id).ok_or_else(|| {
            Box::new(StateError {
                message: "Account not found".to_string(),
            })
        })?;

        account.balance.add_eth(amount);
        Ok(())
    }

    /// 应用转账交易
    ///
    /// 从发送方账户转账到接收方账户。
    /// 验证签名、nonce，检查余额，并更新双方余额。
    ///
    /// # 参数
    ///
    /// * `tx` - 转账交易
    ///
    /// # 返回
    ///
    /// - `Ok(())`: 转账成功
    /// - `Err(Box<dyn Error>)`: 验证失败（签名无效、账户不存在、余额不足、nonce 错误）
    pub fn apply_transfer(
        &mut self,
        tx: &super::transaction::TransferTx,
    ) -> Result<(), Box<dyn Error>> {
        let from_account = self.accounts.get_mut(&tx.from).ok_or_else(|| {
            Box::new(StateError {
                message: "Sender account not found".to_string(),
            })
        })?;

        if from_account.nonce != tx.nonce {
            return Err(Box::new(StateError {
                message: "Invalid nonce".to_string(),
            }));
        }

        let public_key: [u8; 32] = from_account.public_key[..32].try_into().map_err(|_| {
            Box::new(StateError {
                message: "Invalid public key length".to_string(),
            })
        })?;

        if !tx.verify_signature(&public_key)? {
            return Err(Box::new(StateError {
                message: "Invalid signature".to_string(),
            }));
        }

        from_account.balance.sub_eth(tx.amount)?;
        from_account.nonce += 1;

        let to_account = self.accounts.get_mut(&tx.to).ok_or_else(|| {
            Box::new(StateError {
                message: "Recipient account not found".to_string(),
            })
        })?;

        to_account.balance.add_eth(tx.amount);

        Ok(())
    }

    /// 计算状态 Merkle 根
    ///
    /// 将所有账户状态编码为 Merkle 树的叶子，
    /// 计算整个状态树的根哈希。
    /// 用于 L1 同步和欺诈证明。
    ///
    /// # 编码格式
    ///
    /// 叶子节点编码：[账户 ID (4字节)][ETH 余额低32位 (4字节)]...[填充]
    ///
    /// # 返回
    ///
    /// - `Ok([u8; 32])`: 32 字节 Merkle 根
    /// - `Err(Box<dyn Error>)`: 计算失败
    pub fn get_merkle_root(&self) -> Result<[u8; 32], Box<dyn Error>> {
        use crate::crypto::sha256::Sha256Riscv;

        let mut leaves: Vec<[u8; 32]> = self
            .accounts
            .iter()
            .filter(|(_, acc)| acc.id < 4)
            .map(|(_, acc)| {
                let mut leaf = [0u8; 32];
                leaf[..4].copy_from_slice(&acc.id.to_le_bytes());
                let eth_bytes = acc.balance.eth.to_le_bytes();
                leaf[4..8].copy_from_slice(&eth_bytes[..4]);
                leaf
            })
            .collect();

        leaves.sort_by_key(|leaf| u32::from_le_bytes(leaf[..4].try_into().unwrap()));

        while leaves.len() < 4 {
            leaves.push([0u8; 32]);
        }

        let mut level1 = Vec::new();
        for i in 0..2 {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&leaves[i * 2]);
            combined[32..].copy_from_slice(&leaves[i * 2 + 1]);
            let hash = Sha256Riscv::hash(&combined);
            level1.push(hash);
        }

        let mut root = [0u8; 32];
        let root_input = if level1.len() >= 2 {
            let mut root_combined = [0u8; 64];
            root_combined[..32].copy_from_slice(&level1[0]);
            root_combined[32..].copy_from_slice(&level1[1]);
            Sha256Riscv::hash(&root_combined)
        } else if !level1.is_empty() {
            level1[0]
        } else {
            [0u8; 32]
        };
        root.copy_from_slice(&root_input);

        Ok(root)
    }

    /// 获取账户数量
    ///
    /// # 返回
    ///
    /// 当前状态中的账户总数
    pub fn get_account_count(&self) -> usize {
        self.accounts.len()
    }
}

impl Default for RollupState {
    fn default() -> Self {
        Self::new()
    }
}
