//! Rollup 模块
//!
//! 提供 ZK Rollup 核心功能，包括：
//! - 状态管理：账户、余额、转账
//! - 零知识证明：Groth16 协议
//! - 交易处理：转账交易
//!
//! # 模块结构
//!
//! - `state`: Rollup 状态管理
//! - `transaction`: 交易类型
//! - `zk_proof`: ZK Proof 系统
//!
//! # 使用示例
//!
//! ```rust
//! use rollup::state::{Account, Balance, RollupState};
//! use rollup::transaction::{TransferTx, Transaction};
//! use rollup::zk_proof::{ZKGroth16, PublicInput};
//!
//! // 状态管理
//! let mut state = RollupState::new();
//! let account = Account { id: 0, ... };
//! state.create_account(account).unwrap();
//!
//! // ZK Proof
//! let mut groth16 = ZKGroth16::new();
//! let vk = groth16.setup();
//! let proof = groth16.generate_proof(&witness).unwrap();
//! ```

pub mod state;
pub mod transaction;
pub mod zk_proof;

#[cfg(test)]
mod zk_proof_tests;
