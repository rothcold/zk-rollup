//! Crypto 模块
//!
//! 提供完整的加密功能支持，包括：
//! - AES-256 对称加密
//! - SHA-256 哈希计算
//! - Ed25519 椭圆曲线签名
//! - Merkle 树操作
//! - RISC-V 硬件加速抽象
//!
//! # 模块结构
//!
//! - `aes`: AES-256 加密/解密
//! - `sha256`: SHA-256 哈希
//! - `ec`: Ed25519 椭圆曲线
//! - `hash`: 高级哈希操作
//! - `riscv_ext`: RISC-V 加速器抽象
//!
//! # 使用示例
//!
//! ```rust
//! use crypto::aes::Aes256Riscv;
//! use crypto::sha256::Sha256Riscv;
//! use crypto::ec::Ed25519Riscv;
//!
//! // AES-256 加密
//! let aes = Aes256Riscv::new();
//! let encrypted = aes.encrypt_aes256(b"data", &[0u8; 32]).unwrap();
//!
//! // SHA-256 哈希
//! let hash = Sha256Riscv::hash(b"data");
//!
//! // Ed25519 签名
//! let ec = Ed25519Riscv::new();
//! let (sk, pk) = ec.keygen();
//! let signature = ec.sign(&sk, b"message").unwrap();
//! ```

pub mod aes;
pub mod ec;
pub mod hash;
pub mod riscv_ext;
pub mod sha256;

#[cfg(test)]
mod riscv_tests;
#[cfg(test)]
mod hash_tests;
