//! TEE (Trusted Execution Environment) 模块
//!
//! 提供可信执行环境功能，包括：
//! - Enclave 管理
//! - 远程认证
//! - 安全存储
//!
//! # 模块结构
//!
//! - `enclave`: Enclave 创建和管理
//! - `attestation`: 远程认证
//! - `secure_storage`: Enclave 安全存储
//!
//! # 安全特性
//!
//! - 内存加密：Enclave 数据受硬件保护
//! - 隔离执行：与操作系统隔离
//! - 远程认证：可向第三方证明 Enclave 身份
//!
//! # 使用示例
//!
//! ```rust
//! use tee::enclave::{EnclaveConfig, TeeEnclave};
//! use tee::attestation::{AttestationReport, RemoteAttestation};
//! use tee::secure_storage::SecureStorage;
//!
//! // 创建 Enclave
//! let enclave = TeeEnclave::new(EnclaveConfig::default()).unwrap();
//!
//! // 数据密封
//! let sealed = enclave.seal_data(b"sensitive").unwrap();
//!
//! // 安全存储
//! let storage = SecureStorage::new("my_storage".to_string());
//! storage.write("key", &EncryptedData::new(vec![])).unwrap();
//! ```

pub mod attestation;
pub mod enclave;
pub mod secure_storage;

#[cfg(test)]
mod attestation_tests;
