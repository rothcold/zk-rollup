/// AES-256 加密模块，支持 RISC-V 硬件加速
///
/// 该模块提供 AES-256 对称加密算法的实现，支持软件实现和 RISC-V 硬件加速。
/// AES-256 是 NIST 标准的高级加密算法，使用 256 位密钥提供高安全性。

#[allow(dead_code)]
use crate::crypto::riscv_ext::RiscVCryptoExt;
use std::error::Error;
use std::fmt;

/// AES-256 加密/解密操作中发生的错误
#[allow(dead_code)]
#[derive(Debug)]
pub struct Aes256Error {
    message: String,
}

impl fmt::Display for Aes256Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AES-256 Error: {}", self.message)
    }
}

impl Error for Aes256Error {}

/// AES-256 加密器，支持 RISC-V 硬件加速
#[allow(dead_code)]
pub struct Aes256Riscv {
    accelerator: Box<dyn RiscVCryptoExt>,
    expanded_key: Vec<u8>,
}

#[allow(dead_code)]
impl Aes256Riscv {
    /// 创建新的 AES-256 加密器实例
    ///
    /// 初始化时自动创建 RISC-V 硬件加速器实例。
    /// 如果硬件加速器不可用，将使用软件回退实现。
    ///
    /// # 返回
    ///
    /// 新的 `Aes256Riscv` 实例，可立即用于加密/解密操作
    pub fn new() -> Self {
        Aes256Riscv {
            accelerator: Box::new(crate::crypto::riscv_ext::HardwareAccelerator::new()),
            expanded_key: vec![],
        }
    }

    /// 执行 AES-256 密钥扩展算法
    ///
    /// 将 256 位主密钥扩展为 240 字节的轮密钥，用于 AES-256 的 14 轮加密。
    /// 密钥扩展包括：RotWord、S-Box 替换和轮常数 (RCon) 异或。
    ///
    /// # 参数
    ///
    /// * `key` - 256 位（32 字节）主密钥，必须保密且随机生成
    ///
    /// # 返回
    ///
    /// - `Ok(Vec<u8>)`: 240 字节的扩展密钥
    /// - `Err(Box<dyn Error>)`: 密钥无效或处理失败
    ///
    /// # 扩展密钥布局
    ///
    /// 扩展密钥前 32 字节与主密钥相同，后续每轮 16 字节，
    /// 共 15 轮需要 240 字节扩展密钥。
    pub fn key_expansion(&mut self, key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut round_keys = vec![0u8; 240];
        round_keys[..32].copy_from_slice(key);

        for i in 1..=14 {
            let start = (i - 1) * 16;
            let prev13 = round_keys[start + 13];
            let prev14 = round_keys[start + 14];
            let prev15 = round_keys[start + 15];
            let prev12 = round_keys[start + 12];

            let rot_word = [prev13, prev14, prev15, prev12];
            let mut substituted = [0u8; 4];
            for (j, byte) in rot_word.iter().enumerate() {
                substituted[j] = Self::substitute_byte(*byte);
            }

            let rcon = Self::rcon(i);

            for j in 0..4 {
                round_keys[start + 16 + j] = round_keys[start + j] ^ substituted[j] ^ rcon[j];
            }

            for j in 1..4 {
                let idx = start + 16 + j;
                let prev_idx = idx - 16;
                round_keys[idx] = round_keys[prev_idx] ^ round_keys[start + 16 + j - 1];
            }
        }

        self.expanded_key = round_keys.clone();
        Ok(round_keys)
    }

    /// S-Box 字节替换表
    ///
    /// AES S-Box 是固定的双射替换表，用于密钥扩展和字节替换操作。
    /// 每个输入字节映射到对应的输出字节，提供非线性变换。
    #[allow(dead_code)]
    fn substitute_byte(byte: u8) -> u8 {
        match byte {
            0x00 => 0x63,
            0x01 => 0x7c,
            0x02 => 0x77,
            0x03 => 0x7b,
            0x04 => 0xf2,
            0x05 => 0x6b,
            0x06 => 0x6f,
            0x07 => 0xc5,
            0x08 => 0x30,
            0x09 => 0x01,
            0x0a => 0x67,
            0x0b => 0x2b,
            0x0c => 0xfe,
            0x0d => 0xd7,
            0x0e => 0xab,
            0x0f => 0x76,
            0x10 => 0xca,
            0x11 => 0x82,
            0x12 => 0xc9,
            0x13 => 0x7d,
            0x14 => 0xfa,
            0x15 => 0x59,
            0x16 => 0x47,
            0x17 => 0xf0,
            0x18 => 0xae,
            0x19 => 0xd1,
            0x1a => 0x30,
            0x1b => 0xa5,
            0x1c => 0xf3,
            0x1d => 0xac,
            0x1e => 0xe2,
            0x1f => 0x3f,
            0x20 => 0x52,
            0x21 => 0x6c,
            0x22 => 0x6b,
            0x23 => 0xfe,
            0x24 => 0x14,
            0x25 => 0xf7,
            0x26 => 0x2a,
            0x27 => 0xed,
            0x28 => 0x24,
            0x29 => 0x82,
            0x2a => 0xc5,
            0x2b => 0x7f,
            0x2c => 0x11,
            0x2d => 0xb0,
            0x2e => 0x5f,
            0x2f => 0x14,
            0x30 => 0x56,
            0x31 => 0x08,
            0x32 => 0x12,
            0x33 => 0x77,
            0x34 => 0x13,
            0x35 => 0x94,
            0x36 => 0xa0,
            0x37 => 0xf9,
            0x38 => 0xe1,
            0x39 => 0xd8,
            0x3a => 0x53,
            0x3b => 0x03,
            0x3c => 0x1d,
            0x3d => 0x24,
            0x3e => 0x20,
            0x3f => 0xbd,
            0x40 => 0x34,
            0x41 => 0x58,
            0x42 => 0x08,
            0x43 => 0xb7,
            0x44 => 0x35,
            0x45 => 0xd5,
            0x46 => 0xc0,
            0x47 => 0xa7,
            0x48 => 0x9d,
            0x49 => 0x84,
            0x4a => 0x70,
            0x4b => 0x8e,
            0x4c => 0xb1,
            0x4d => 0xc4,
            0x4e => 0x58,
            0x4f => 0xf0,
            0x50 => 0xda,
            0x51 => 0x66,
            0x52 => 0x11,
            0x53 => 0xd0,
            0x54 => 0x50,
            0x55 => 0xf8,
            0x56 => 0x28,
            0x57 => 0x8c,
            0x58 => 0xb0,
            0x59 => 0x4e,
            0x5a => 0x5a,
            0x5b => 0x18,
            0x5c => 0xa4,
            0x5d => 0x3c,
            0x5e => 0xc1,
            0x5f => 0xa8,
            0x60 => 0x51,
            0x61 => 0x21,
            0x62 => 0x72,
            0x63 => 0x74,
            0x64 => 0xb9,
            0x65 => 0xf1,
            0x66 => 0x09,
            0x67 => 0xc5,
            0x68 => 0x6a,
            0x69 => 0xaa,
            0x6a => 0xe5,
            0x6b => 0x15,
            0x6c => 0x2d,
            0x6d => 0xe2,
            0x6e => 0xf4,
            0x6f => 0x0e,
            0x70 => 0x12,
            0x71 => 0xeb,
            0x72 => 0x22,
            0x73 => 0x0c,
            0x74 => 0xd6,
            0x75 => 0xeb,
            0x76 => 0x6a,
            0x77 => 0x19,
            0x78 => 0x55,
            0x79 => 0x74,
            0x7a => 0xa2,
            0x7b => 0x25,
            0x7c => 0x17,
            0x7d => 0x2b,
            0x7e => 0x41,
            0x7f => 0x56,
            0x80 => 0x21,
            0x81 => 0xcf,
            0x82 => 0x4f,
            0x83 => 0xd5,
            0x84 => 0x43,
            0x85 => 0x29,
            0x86 => 0x55,
            0x87 => 0x6b,
            0x88 => 0xca,
            0x89 => 0x73,
            0x8a => 0x22,
            0x8b => 0x95,
            0x8c => 0x3f,
            0x8d => 0x0f,
            0x8e => 0x02,
            0x8f => 0xc1,
            0x90 => 0xaf,
            0x91 => 0xd9,
            0x92 => 0x6a,
            0x93 => 0x2b,
            0x94 => 0x08,
            0x95 => 0x9a,
            0x96 => 0x80,
            0x97 => 0x86,
            0x98 => 0x07,
            0x99 => 0x91,
            0x9a => 0x12,
            0x9b => 0xce,
            0x9c => 0xfa,
            0x9d => 0xea,
            0x9e => 0xfb,
            0x9f => 0x43,
            0xa0 => 0xd1,
            0xa1 => 0x18,
            0xa2 => 0x0d,
            0xa3 => 0x26,
            0xa4 => 0x69,
            0xa5 => 0x6c,
            0xa6 => 0x20,
            0xa7 => 0xfc,
            0xa8 => 0xb6,
            0xa9 => 0x51,
            0xaa => 0x10,
            0xab => 0x8f,
            0xac => 0xe8,
            0xad => 0xf8,
            0xae => 0x19,
            0xaf => 0x0c,
            0xb0 => 0xd7,
            0xb1 => 0xc7,
            0xb2 => 0x87,
            0xb3 => 0x38,
            0xb4 => 0x47,
            0xb5 => 0xed,
            0xb6 => 0x6c,
            0xb7 => 0x3b,
            0xb8 => 0xcc,
            0xb9 => 0xb7,
            0xba => 0x40,
            0xbb => 0xd9,
            0xbc => 0x5e,
            0xbd => 0x42,
            0xbe => 0x7a,
            0xbf => 0x09,
            0xc0 => 0x4f,
            0xc1 => 0xc7,
            0xc2 => 0x22,
            0xc3 => 0x5d,
            0xc4 => 0x52,
            0xc5 => 0x11,
            0xc6 => 0x23,
            0xc7 => 0x44,
            0xc8 => 0x8d,
            0xc9 => 0x9a,
            0xca => 0x87,
            0xcb => 0x9c,
            0xcc => 0x1a,
            0xcd => 0xbf,
            0xce => 0xe4,
            0xcf => 0x2d,
            0xd0 => 0x8a,
            0xd1 => 0x73,
            0xd2 => 0x16,
            0xd3 => 0x1c,
            0xd4 => 0x5f,
            0xd5 => 0xbc,
            0xd6 => 0x37,
            0xd7 => 0x74,
            0xd8 => 0xd4,
            0xd9 => 0x9e,
            0xda => 0xf5,
            0xdb => 0x7e,
            0xdc => 0xc5,
            0xdd => 0xf9,
            0xde => 0x2a,
            0xdf => 0x68,
            0xe0 => 0x3d,
            0xe1 => 0xe0,
            0xe2 => 0x4e,
            0xe3 => 0x13,
            0xe4 => 0x12,
            0xe5 => 0x4a,
            0xe6 => 0x2f,
            0xe7 => 0x0c,
            0xe8 => 0xa1,
            0xe9 => 0xc3,
            0xea => 0xf4,
            0xeb => 0x1e,
            0xec => 0xc8,
            0xed => 0x3e,
            0xee => 0xef,
            0xef => 0x67,
            0xf0 => 0x47,
            0xf1 => 0xf7,
            0xf2 => 0x0a,
            0xf3 => 0x7d,
            0xf4 => 0xf1,
            0xf5 => 0xd2,
            0xf6 => 0x2b,
            0xf7 => 0x9f,
            0xf8 => 0xa4,
            0xf9 => 0x7c,
            0xfa => 0xde,
            0xfb => 0x27,
            0xfc => 0x10,
            0xfd => 0x8a,
            0xfe => 0x05,
            0xff => 0x01,
        }
    }

    /// 生成轮常数 (RCon)
    ///
    /// RCon 是密钥扩展中用于每一轮的常数，确保轮密钥的唯一性。
    /// 第 n 轮的 RCon 值等于 2^(n-1) 在有限域 GF(2^8) 中的表示。
    ///
    /// # 参数
    ///
    /// * `round` - 当前轮数（1-14）
    ///
    /// # 返回
    ///
    /// 4 字节轮常数数组，第一字节为有效值
    fn rcon(round: usize) -> [u8; 4] {
        let mut rcon = [0u8; 4];
        rcon[0] = match round {
            1 => 0x01,
            2 => 0x02,
            3 => 0x04,
            4 => 0x08,
            5 => 0x10,
            6 => 0x20,
            7 => 0x40,
            8 => 0x80,
            9 => 0x1b,
            10 => 0x36,
            _ => 0x00,
        };
        rcon
    }

    /// 使用 AES-256 加密数据
    ///
    /// 对明文进行 AES-256 加密，支持 RISC-V 硬件加速。
    /// 加密过程包括：明文填充、14 轮 AES 变换（SubBytes、ShiftRows、MixColumns、AddRoundKey）。
    ///
    /// # 参数
    ///
    /// * `plaintext` - 要加密的明文数据，可为任意长度
    /// * `key` - 256 位（32 字节）加密密钥，必须与解密密钥相同
    ///
    /// # 返回
    ///
    /// - `Ok(Vec<u8>)`: 加密后的密文，长度为明文长度（无额外填充）
    /// - `Err(Box<dyn Error>)`: 加密失败（如密钥无效、硬件错误）
    pub fn encrypt_aes256(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.accelerator.copr_encrypt_aes256(plaintext, key)
    }

    /// 使用 AES-256 解密数据
    ///
    /// 对 AES-256 加密的密文进行解密，是 `encrypt_aes256` 的逆操作。
    /// 解密过程执行与加密相反的 14 轮变换。
    ///
    /// # 参数
    ///
    /// * `ciphertext` - 要解密的密文数据
    /// * `key` - 256 位（32 字节）解密密钥，必须与加密密钥相同
    ///
    /// # 返回
    ///
    /// - `Ok(Vec<u8>)`: 解密后的明文
    /// - `Err(Box<dyn Error>)`: 解密失败（如密钥错误、密文损坏）
    pub fn decrypt_aes256(
        &self,
        ciphertext: &[u8],
        key: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.accelerator.copr_decrypt_aes256(ciphertext, key)
    }
}

impl Default for Aes256Riscv {
    fn default() -> Self {
        Self::new()
    }
}
