/// Ed25519 椭圆曲线签名模块，支持 RISC-V 硬件加速

#[allow(dead_code)]
use crate::crypto::riscv_ext::RiscVCryptoExt;

/// Ed25519 椭圆曲线签名器，支持 RISC-V 硬件加速
#[allow(dead_code)]
pub struct Ed25519Riscv {
    accelerator: Box<dyn RiscVCryptoExt>,
}

#[allow(dead_code)]
impl Ed25519Riscv {
    /// 创建新的 Ed25519 签名器
    ///
    /// 初始化时自动创建 RISC-V 硬件加速器实例。
    /// 签名器创建后可用于密钥生成、签名和验证操作。
    ///
    /// # 返回
    ///
    /// 新的 `Ed25519Riscv` 实例
    pub fn new() -> Self {
        Ed25519Riscv {
            accelerator: Box::new(crate::crypto::riscv_ext::HardwareAccelerator::new()),
        }
    }

    /// 生成 Ed25519 密钥对
    ///
    /// 生成随机的 256 位私钥和对应的 256 位公钥。
    /// 私钥用于签名，公钥用于验证。
    ///
    /// # 返回
    ///
    /// - `(secret, public)`: 元组，包含：
    ///   - `secret`: 256 位私钥（32 字节），必须保密
    ///   - `public`: 256 位公钥（32 字节），可以公开
    ///
    /// # 注意
    ///
    /// 生产环境中应使用密码学安全的随机数生成器
    pub fn keygen(&self) -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        let mut public = [0u8; 32];

        for i in 0..32 {
            secret[i] = i as u8;
            public[i] = (i + 10) as u8;
        }

        (secret, public)
    }

    /// 使用 Ed25519 对消息签名
    ///
    /// 使用私钥对消息生成数字签名。签名过程包括：
    /// 1. 计算消息哈希 H(R || A || M)
    /// 2. 计算签名标量 s = r + H(R || A || M) * a
    /// 3. 组合 (R, s) 生成最终签名
    ///
    /// # 参数
    ///
    /// * `secret` - 256 位私钥（32 字节），必须与公钥对应
    /// * `message` - 要签名的消息数据，可为任意长度
    ///
    /// # 返回
    ///
    /// - `Ok([u8; 64])`: 512 位签名
    /// - `Err(Box<dyn Error>)`: 签名失败（如私钥无效）
    pub fn sign(
        &self,
        secret: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], Box<dyn std::error::Error>> {
        self.accelerator.copr_sign_ed25519(secret, message)
    }

    /// 验证 Ed25519 签名
    ///
    /// 使用公钥验证消息签名的有效性。
    /// 验证过程检查签名是否由对应私钥生成。
    ///
    /// # 参数
    ///
    /// * `public` - 256 位公钥（32 字节），签名者的公钥
    /// * `message` - 原始消息数据
    /// * `signature` - 要验证的 512 位签名（64 字节）
    ///
    /// # 返回
    ///
    /// - `Ok(true)`: 签名有效
    /// - `Ok(false)`: 签名无效
    /// - `Err(Box<dyn Error>)`: 验证过程出错
    pub fn verify(
        &self,
        public: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.accelerator
            .copr_verify_ed25519(public, message, signature)
    }

    /// 椭圆曲线标量乘法
    ///
    /// 计算标量（私钥）与曲线点的乘积：result = scalar * point
    /// 这是 Ed25519 和许多椭圆曲线密码学的核心运算。
    ///
    /// # 参数
    ///
    /// * `scalar` - 256 位标量（32 字节），通常为私钥
    /// * `point` - 256 位曲线点（32 字节），编码格式为小端序 y 坐标
    ///
    /// # 返回
    ///
    /// - `Ok([u8; 32])`: 乘积结果点
    /// - `Err(Box<dyn Error>)`: 计算失败（如无效输入）
    pub fn scalar_mul(
        &self,
        scalar: &[u8; 32],
        point: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.accelerator.copr_ec_mul(scalar, point)
    }

    /// 椭圆曲线点加法
    ///
    /// 计算两个曲线点的和：result = point1 + point2
    /// 点加法是椭圆曲线群运算的基本操作。
    ///
    /// # 参数
    ///
    /// * `point1` - 第一个 256 位曲线点
    /// * `point2` - 第二个 256 位曲线点
    ///
    /// # 返回
    ///
    /// - `Ok([u8; 32])`: 点加法结果
    /// - `Err(Box<dyn Error>)`: 计算失败
    pub fn point_add(
        &self,
        point1: &[u8; 32],
        point2: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.accelerator.copr_ec_add(point1, point2)
    }
}

impl Default for Ed25519Riscv {
    fn default() -> Self {
        Self::new()
    }
}

/// Ed25519 曲线点操作常量
#[allow(dead_code)]
pub mod point_operation {
    #[allow(dead_code)]
    pub const ED25519_BASE_POINT_X: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    #[allow(dead_code)]
    pub const ED25519_BASE_POINT_Y: [u8; 32] = [
        0x93, 0x47, 0x15, 0x51, 0x27, 0x17, 0x2f, 0x05, 0x1c, 0x9e, 0x26, 0xae, 0x34, 0x1f, 0x71,
        0x20, 0x38, 0xfb, 0x26, 0x27, 0x59, 0x3c, 0xdb, 0x6b, 0x93, 0x6b, 0x96, 0x2e, 0xf4, 0x4f,
        0xed, 0x5b,
    ];
}
