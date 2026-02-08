#[allow(dead_code)]
use crate::crypto::ec::Ed25519Riscv;
/// Rollup 交易模块
///
/// 该模块定义 ZK Rollup 支持的交易类型和交易构建工具。

#[allow(dead_code)]
use serde::{Deserialize, Serialize};

/// 转账交易结构
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTx {
    pub from: u32,
    pub to: u32,
    pub amount: u64,
    pub nonce: u32,
    pub signature: Vec<u8>,
}

impl TransferTx {
    /// 获取签名的 64 字节数组引用
    ///
    /// # 返回
    ///
    /// 64 字节签名的切片引用，如果签名长度不是 64 则返回 None
    pub fn signature_bytes(&self) -> Option<&[u8; 64]> {
        self.signature.as_slice().try_into().ok()
    }

    /// 创建待签名的交易消息
    ///
    /// 将交易的关键字段编码为待签名的消息。
    /// 消息格式: [from (4字节)][to (4字节)][amount (8字节)][nonce (4字节)]
    ///
    /// # 返回
    ///
    /// 20 字节的交易消息
    pub fn to_message(&self) -> [u8; 20] {
        let mut message = [0u8; 20];
        message[..4].copy_from_slice(&self.from.to_le_bytes());
        message[4..8].copy_from_slice(&self.to.to_le_bytes());
        message[8..16].copy_from_slice(&self.amount.to_le_bytes());
        message[16..20].copy_from_slice(&self.nonce.to_le_bytes());
        message
    }

    /// 使用私钥对交易签名
    ///
    /// 使用 Ed25519 私钥对交易消息进行签名。
    /// 签名后签名字段会被填充。
    ///
    /// # 参数
    ///
    /// * `secret` - 32 字节 Ed25519 私钥
    ///
    /// # 返回
    ///
    /// - `Ok(())`: 签名成功
    /// - `Err(Box<dyn Error>)`: 签名失败
    pub fn sign(&mut self, secret: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let message = self.to_message();
        let ed25519 = Ed25519Riscv::new();
        let signature = ed25519.sign(secret, &message)?;
        self.signature = signature.to_vec();
        Ok(())
    }

    /// 验证交易签名
    ///
    /// 使用发送方公钥验证交易签名的有效性。
    ///
    /// # 参数
    ///
    /// * `public_key` - 发送方的 32 字节 Ed25519 公钥
    ///
    /// # 返回
    ///
    /// - `Ok(true)`: 签名有效
    /// - `Ok(false)`: 签名无效
    /// - `Err(Box<dyn Error>)`: 验证过程出错
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let message = self.to_message();
        let sig_array: [u8; 64] = self.signature[..64].try_into().map_err(|_| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid signature length",
            ))
        })?;
        let ed25519 = Ed25519Riscv::new();
        ed25519.verify(public_key, &message, &sig_array)
    }
}

/// 交易类型枚举
///
/// 支持多种交易类型，当前仅实现转账。
/// 未来可扩展：兑换、合约调用、批量交易等。
///
/// # 变体
///
/// * `Transfer(TransferTx)`: 转账交易
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transaction {
    /// 转账交易变体
    Transfer(TransferTx),
}

impl Transaction {
    /// 获取交易的发送方账户 ID
    ///
    /// # 返回
    ///
    /// - `Some(u32)`: 发送方账户 ID
    /// - `None`: 交易类型不支持
    pub fn get_sender(&self) -> Option<u32> {
        match self {
            Transaction::Transfer(tx) => Some(tx.from),
        }
    }

    /// 获取交易的 nonce 值
    ///
    /// # 返回
    ///
    /// 交易的 nonce 值
    pub fn get_nonce(&self) -> u32 {
        match self {
            Transaction::Transfer(tx) => tx.nonce,
        }
    }
}

/// 交易构建器
///
/// 提供流式 API 构造交易对象。
/// 确保必填字段被设置后才构建交易。
///
/// # 使用方式
///
/// ```rust
/// let tx = TransactionBuilder::new()
///     .from(0)           // 必填
///     .to(1)             // 必填
///     .amount(100)       // 必填
///     .nonce(0)          // 可选，默认为 0
///     .build()           // 构建交易
/// ```
#[derive(Debug)]
pub struct TransactionBuilder {
    /// 发送方账户 ID
    from: Option<u32>,
    /// 接收方账户 ID
    to: Option<u32>,
    /// 转账金额
    amount: Option<u64>,
    /// 交易 nonce
    nonce: Option<u32>,
}

impl TransactionBuilder {
    /// 创建新的交易构建器
    ///
    /// # 返回
    ///
    /// 空的 `TransactionBuilder` 实例
    pub fn new() -> Self {
        TransactionBuilder {
            from: None,
            to: None,
            amount: None,
            nonce: None,
        }
    }

    /// 设置发送方账户 ID
    ///
    /// # 参数
    ///
    /// * `id` - 发送方账户 ID
    ///
    /// # 返回
    ///
    /// 更新后的构建器
    pub fn from(mut self, id: u32) -> Self {
        self.from = Some(id);
        self
    }

    /// 设置接收方账户 ID
    ///
    /// # 参数
    ///
    /// * `id` - 接收方账户 ID
    ///
    /// # 返回
    ///
    /// 更新后的构建器
    pub fn to(mut self, id: u32) -> Self {
        self.to = Some(id);
        self
    }

    /// 设置转账金额
    ///
    /// # 参数
    ///
    /// * `amount` - 转账金额（wei）
    ///
    /// # 返回
    ///
    /// 更新后的构建器
    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// 设置交易 nonce
    ///
    /// # 参数
    ///
    /// * `nonce` - 交易序列号
    ///
    /// # 返回
    ///
    /// 更新后的构建器
    pub fn nonce(mut self, nonce: u32) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// 构建交易对象
    ///
    /// 检查所有必填字段，创建 `Transaction` 实例。
    /// 签名字段初始为零，需要外部签名。
    ///
    /// # 返回
    ///
    /// - `Ok(Transaction)`: 构建成功
    /// - `Err(Box<dyn Error>)`: 缺少必填字段
    pub fn build(self) -> Result<Transaction, Box<dyn std::error::Error>> {
        let tx = TransferTx {
            from: self.from.ok_or("Missing from address")?,
            to: self.to.ok_or("Missing to address")?,
            amount: self.amount.ok_or("Missing amount")?,
            nonce: self.nonce.unwrap_or(0),
            signature: vec![0u8; 64],
        };

        Ok(Transaction::Transfer(tx))
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
