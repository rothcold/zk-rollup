//! ZK Rollup 主程序入口
//!
//! 该程序演示了 ZK Rollup 的核心功能测试，包括：
//! 1. RISC-V 加密扩展（AES-256、SHA-256、Ed25519）
//! 2. TEE Enclave 功能（Enclave、认证、安全存储）
//! 3. ZK Proof 系统（证明生成、验证、MSM 加速）
//! 4. Rollup 状态管理（账户创建、转账、Merkle 根）
//!
//! # 运行方式
//!
//! ```bash
//! cargo run
//! ```
//!
//! # 输出说明
//!
//! 程序依次测试各模块功能，每个模块通过后显示 "OK"。

mod crypto;
mod rollup;
mod tee;

/// ZK Rollup 主入口函数
///
/// 运行所有核心模块的功能测试：
/// 1. RISC-V 加密扩展测试
/// 2. TEE Enclave 功能测试
/// 3. ZK Proof 系统测试
/// 4. Rollup 状态管理测试
fn main() {
    println!("ZK Rollup with RISC-V Optimization and TEE Encryption");
    println!("======================================================");

    println!("\n[1] Testing RISC-V Crypto Extensions...");
    test_riscv_crypto();

    println!("\n[2] Testing TEE Enclave...");
    test_tee_enclave();

    println!("\n[3] Testing ZK Proof System...");
    test_zk_proof();

    println!("\n[4] Testing Rollup State...");
    test_rollup_state();

    println!("\nAll tests passed successfully!");
}

/// 测试 RISC-V 加密扩展模块
///
/// 测试以下加密操作：
/// - AES-256 加密/解密
/// - SHA-256 哈希计算
/// - Ed25519 签名/验证
fn test_riscv_crypto() {
    use crypto::aes::Aes256Riscv;
    use crypto::ec::Ed25519Riscv;
    use crypto::sha256::Sha256Riscv;

    // 测试 AES-256
    let aes = Aes256Riscv::new();
    let key = [0u8; 32];
    let plaintext = b"Test AES-256 encryption";
    let encrypted = aes.encrypt_aes256(plaintext, &key).unwrap();
    let decrypted = aes.decrypt_aes256(&encrypted, &key).unwrap();
    assert_eq!(plaintext, decrypted.as_slice());

    // 测试 SHA-256
    let _sha256 = Sha256Riscv::new();
    let data = b"Test SHA-256 hashing";
    let hash = Sha256Riscv::hash(data);
    assert_eq!(hash.len(), 32);

    // 测试 Ed25519
    let ed25519 = Ed25519Riscv::new();
    let (sk, pk) = ed25519.keygen();
    let message = b"Test Ed25519 signature";
    let signature = ed25519.sign(&sk, message).unwrap();
    let valid = ed25519.verify(&pk, message, &signature).unwrap();
    assert!(valid);

    println!("  - AES-256: OK");
    println!("  - SHA-256: OK");
    println!("  - Ed25519: OK");
}

/// 测试 TEE Enclave 模块
///
/// 测试以下功能：
/// - Enclave 创建和数据密封/解封
/// - 远程认证报告生成
/// - 安全存储读写操作
fn test_tee_enclave() {
    use tee::attestation::{AttestationReport, RemoteAttestation};
    use tee::enclave::EnclaveConfig;
    use tee::enclave::TeeEnclave;
    use tee::secure_storage::{EncryptedData, SecureStorage};

    // 测试 Enclave
    let config = EnclaveConfig::default();
    let enclave = TeeEnclave::new(config).unwrap();
    assert!(enclave.get_id() > 0);

    // 测试数据密封
    let data = b"Sensitive data";
    let sealed = enclave.seal_data(data).unwrap();
    let unsealed = enclave.unseal_data(&sealed).unwrap();
    assert_eq!(data, unsealed.as_slice());

    // 测试认证报告
    let report = AttestationReport::generate(enclave.get_id(), &[1, 2, 3, 4]).unwrap();
    assert_eq!(report.enclave_id, enclave.get_id());

    // 测试远程认证
    let attestation = RemoteAttestation::new();
    let evidence = attestation.generate_evidence(report).unwrap();
    assert!(evidence.verify().unwrap());

    // 测试安全存储
    let storage = SecureStorage::new("test".to_string());
    let encrypted_data = EncryptedData::new(vec![1, 2, 3]);
    storage.write("key1", &encrypted_data).unwrap();
    assert!(storage.exists("key1").unwrap());
    storage.delete("key1").unwrap();
    assert!(!storage.exists("key1").unwrap());

    println!("  - Enclave: OK");
    println!("  - Attestation: OK");
    println!("  - Secure Storage: OK");
}

/// 测试 ZK Proof 系统
///
/// 测试以下功能：
/// - Groth16 验证密钥生成
/// - 零知识证明生成
/// - 证明验证
/// - MSM 加速运算
fn test_zk_proof() {
    use rollup::zk_proof::{PublicInput, ZKGroth16};

    // 创建 Groth16 证明系统
    let mut groth16 = ZKGroth16::new();
    let vk = groth16.setup();

    // 生成证明
    let witness = vec![1u8; 32];
    let proof = groth16.generate_proof(&witness).unwrap();
    assert!(!proof.pi_a.is_empty());
    assert!(!proof.pi_b.is_empty());

    // 验证证明
    let public_input = PublicInput::from_witness(&witness);
    let valid = groth16.verify(&vk, &proof, &public_input).unwrap();
    assert!(valid);

    // 测试 MSM 加速
    let points: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 32]).collect();
    let scalars: Vec<Vec<u8>> = (0..4).map(|i| vec![(i + 1) as u8; 32]).collect();
    let msm_result = groth16.accelerated_msm(&points, &scalars).unwrap();
    assert_eq!(msm_result.len(), 32);

    println!("  - Groth16 Setup: OK");
    println!("  - Proof Generation: OK");
    println!("  - Proof Verification: OK");
    println!("  - MSM Acceleration: OK");
}

/// 测试 Rollup 状态管理
///
/// 测试以下功能：
/// - 账户创建
/// - 余额更新
/// - 转账交易（含签名验证）
/// - Merkle 根计算
fn test_rollup_state() {
    use crypto::ec::Ed25519Riscv;
    use rollup::state::{Account, Balance, RollupState};
    use rollup::transaction::TransferTx;

    // 创建状态
    let mut state = RollupState::new();

    // 生成密钥对
    let ed25519 = Ed25519Riscv::new();
    let (secret_key, public_key) = ed25519.keygen();

    // 创建账户
    let account1 = Account {
        id: 0,
        public_key: public_key.to_vec(),
        nonce: 0,
        balance: Balance::new(),
    };
    let account2 = Account {
        id: 1,
        public_key: vec![2u8; 32],
        nonce: 0,
        balance: Balance::new(),
    };

    state.create_account(account1).unwrap();
    state.create_account(account2).unwrap();
    state.update_balance(0, 1000).unwrap();

    // 测试带签名的转账
    let mut tx = TransferTx {
        from: 0,
        to: 1,
        amount: 100,
        nonce: 0,
        signature: vec![0u8; 64],
    };

    // 使用发送方私钥签名
    tx.sign(&secret_key).unwrap();

    // 验证签名
    assert!(tx.verify_signature(&public_key).unwrap());

    // 应用转账
    state.apply_transfer(&tx).unwrap();

    // 验证余额
    let acc0 = state.get_account(0).unwrap();
    let acc1 = state.get_account(1).unwrap();
    assert_eq!(acc0.balance.eth, 900);
    assert_eq!(acc1.balance.eth, 100);

    // 测试无效签名应失败
    let mut invalid_tx = TransferTx {
        from: 0,
        to: 1,
        amount: 50,
        nonce: 1,
        signature: vec![0u8; 64],
    };
    let wrong_secret = [5u8; 32];
    invalid_tx.sign(&wrong_secret).unwrap();
    assert!(state.apply_transfer(&invalid_tx).is_err());

    // 计算 Merkle 根
    let root = state.get_merkle_root().unwrap();
    assert_eq!(root.len(), 32);

    println!("  - Account Creation: OK");
    println!("  - Balance Update: OK");
    println!("  - Transfer: OK");
    println!("  - Signature Verification: OK");
    println!("  - Merkle Root: OK");
}
