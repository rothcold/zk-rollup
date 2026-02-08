#[cfg(test)]
mod riscv_crypto_tests {
    use crate::crypto::aes::Aes256Riscv;
    use crate::crypto::ec::Ed25519Riscv;
    use crate::crypto::riscv_ext::RiscVCryptoExt;
    use crate::crypto::sha256::Sha256Riscv;

    #[test]
    fn test_aes256_riscv_encrypt_decrypt() {
        let crypto = Aes256Riscv::new();
        let key = [0u8; 32];
        let plaintext = b"Hello, ZK Rollup with RISC-V!";

        let encrypted = crypto.encrypt_aes256(plaintext, &key).unwrap();
        let decrypted = crypto.decrypt_aes256(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes256_riscv_key_expansion() {
        let mut crypto = Aes256Riscv::new();
        let key = [0u8; 32];
        let expanded = crypto.key_expansion(&key).unwrap();

        assert_eq!(expanded.len(), 240); // 15 rounds * 16 bytes + 16
    }

    #[test]
    fn test_sha256_riscv_hash() {
        let _hasher = Sha256Riscv::new();
        let data = b"test data for hashing";
        let hash = Sha256Riscv::hash(data);

        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_sha256_riscv_chain() {
        let mut hasher = Sha256Riscv::new();
        hasher.update(b"block1");
        hasher.update(b"block2");
        let final_hash = hasher.finalize();

        assert_eq!(final_hash.len(), 32);
    }

    #[test]
    fn test_ed25519_riscv_keygen() {
        let ec = Ed25519Riscv::new();
        let (sk, pk) = ec.keygen();

        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_ed25519_riscv_sign_verify() {
        let ec = Ed25519Riscv::new();
        let (sk, pk) = ec.keygen();
        let message = b"Test message for signature";

        let signature = ec.sign(&sk, message).unwrap();
        let valid = ec.verify(&pk, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_riscv_crypto_ext_operations() {
        use crate::crypto::riscv_ext::HardwareAccelerator;
        let ext = HardwareAccelerator::new();

        let result = ext.copr_encrypt_aes256(b"test", &[0u8; 32]).unwrap();
        assert!(result.len() >= 4);
    }
}
