# ZK Rollup - RISC-V 优化与 TEE 加密

基于 Rust 的零知识证明 Rollup 实现，支持 RISC-V 硬件加速和可信执行环境（TEE）加密。

## 项目简介

本项目是一个实验性的 ZK Rollup 实现，结合了以下技术特性：

- **零知识证明 (ZK Proofs)**：使用 Groth16 协议生成和验证零知识证明
- **RISC-V 硬件加速**：加密操作（AES-256、SHA-256、Ed25519）支持 RISC-V 扩展加速
- **可信执行环境 (TEE)**：集成 Enclave、远程认证和安全存储

## 技术架构

### 核心模块

```rust
src/
├── crypto/          #│   ├── aes 加密模块
.rs       # AES-256 加密（RISC-V 加速版本）
│   ├── sha256.rs    # SHA-256 哈希（RISC-V 加速版本）
│   ├── ec.rs        # Ed25519 椭圆曲线签名（RISC-V 加速版本）
│   ├── hash.rs      # 通用哈希接口
│   └── riscv_ext.rs # RISC-V 硬件加速器抽象
├── rollup/          # Rollup 核心逻辑
│   ├── state.rs     # Rollup 状态管理（账户、余额、Merkle 树）
│   ├── transaction.rs # 交易类型（转账交易）
│   └── zk_proof.rs  # ZK Proof 系统（Groth16、MSM 加速）
└── tee/             # 可信执行环境
    ├── enclave.rs    # Enclave 管理
    ├── attestation.rs # 远程认证
    └── secure_storage.rs # Enclave 安全存储
```

### 主要特性

#### 1. 加密模块 (crypto)

- **Aes256Riscv**：支持 AES-256 加密/解密，带软件实现和 RISC-V 硬件加速
- **Sha256Riscv**：支持 SHA-256 哈希计算，支持分块更新和硬件加速
- **Ed25519Riscv**：Ed25519 椭圆曲线签名，支持密钥生成、签名和验证

#### 2. Rollup 状态管理 (rollup/state)

- **RollupState**：管理所有账户状态
- **Account**：账户结构，包含公钥、nonce、余额
- **Balance**：多资产余额（ETH + 代币）
- **Merkle Root**：生成账户状态的 Merkle 根

#### 3. 交易处理 (rollup/transaction)

- **Transaction**：交易枚举类型
- **TransferTx**：转账交易结构
- 支持交易序列化（bincode）

#### 4. ZK 证明系统 (rollup/zk_proof)

- **ZKGroth16**：Groth16 零知识证明协议实现
- **加速运算**：MSM（多标量乘法）、FFT、多项式运算的硬件加速
- **证明生成与验证**：完整的证明生命周期管理

#### 5. TEE 模块 (tee)

- **TeeEnclave**：Enclave 实例管理，支持数据密封/解封
- **AttestationReport**：Enclave 认证报告
- **RemoteAttestation**：远程认证机制
- **SecureStorage**：Enclave 内的安全键值存储

## 依赖环境

- Rust 2024 Edition
- 依赖库：
  - `serde` / `serde_json`：序列化
  - `sha2`：SHA-256
  - `aes-gcm`：AES-GCM 加密
  - `curve25519-dalek`：椭圆曲线
  - `blake2`：BLAKE2 哈希
  - `thiserror`：错误处理
  - `bincode`：测试序列化

## 快速开始

### 构建项目

```bash
# Debug 构建
cargo build

# Release 优化构建
cargo build --release

# 类型检查
cargo check
```

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定测试文件
cargo test --test riscv_tests      # 加密模块测试
cargo test --test zk_proof_tests    # ZK 证明测试
cargo test --test tee_enclave_tests # TEE 模块测试

# 运行单个测试
cargo test test_aes256_riscv_encrypt_decrypt
```

### 运行示例

```bash
cargo run
```

运行主程序将依次测试：

1. RISC-V 加密扩展（AES-256、SHA-256、Ed25519）
2. TEE Enclave 功能（Enclave、认证、安全存储）
3. ZK 证明系统（证明生成、验证、MSM 加速）
4. Rollup 状态管理（账户创建、转账、Merkle 根）

## 使用示例

### AES-256 加密

```rust
use crypto::aes::Aes256Riscv;

let aes = Aes256Riscv::new();
let key = [0u8; 32];
let plaintext = b"Hello, ZK Rollup!";

let encrypted = aes.encrypt_aes256(plaintext, &key).unwrap();
let decrypted = aes.decrypt_aes256(&encrypted, &key).unwrap();
assert_eq!(plaintext, decrypted.as_slice());
```

### Rollup 状态管理

```rust
use rollup::state::{Account, Balance, RollupState};
use rollup::transaction::TransferTx;

let mut state = RollupState::new();

// 创建账户
let account = Account {
    id: 0,
    public_key: vec![1u8; 32],
    nonce: 0,
    balance: Balance::new(),
};
state.create_account(account).unwrap();

// 更新余额
state.update_balance(0, 1000).unwrap();

// 转账
let tx = TransferTx {
    from: 0,
    to: 1,
    amount: 100,
    nonce: 0,
    signature: vec![0u8; 64],
};
state.apply_transfer(&tx).unwrap();

// 获取 Merkle 根
let root = state.get_merkle_root().unwrap();
```

### ZK Proof 生成与验证

```rust
use rollup::zk_proof::ZKGroth16;

let mut groth16 = ZKGroth16::new();

// 设置
let vk = groth16.setup();

// 生成证明
let witness = vec![1u8; 32];
let proof = groth16.generate_proof(&witness).unwrap();

// 验证
let public_input = PublicInput::from_witness(&witness);
let valid = groth16.verify(&vk, &proof, &public_input).unwrap();
assert!(valid);
```

### TEE Enclave

```rust
use tee::enclave::{EnclaveConfig, TeeEnclave};

let config = EnclaveConfig::default();
let enclave = TeeEnclave::new(config).unwrap();

// 密封数据
let data = b"Sensitive data";
let sealed = enclave.seal_data(data).unwrap();
let unsealed = enclave.unseal_data(&sealed).unwrap();
assert_eq!(data, unsealed.as_slice());
```

## 代码规范

- 使用 `thiserror` 定义错误类型
- 实现 `Default` trait 用于默认构造
- 使用 `Box<dyn Error>` 进行错误传播
- 硬件加速使用 `Riscv` 后缀命名
- 测试代码放在 `*_tests.rs` 文件中

## 未来方向

- 完整的 Groth16 协议实现
- 真正的 RISC-V 硬件加速后端
- 生产级 TEE 集成（Intel SGX / ARM TrustZone）
- Rollup 批量交易处理
- 轻客户端支持

## 许可证

MIT
