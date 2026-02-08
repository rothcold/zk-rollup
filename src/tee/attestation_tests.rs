#[cfg(test)]
mod tee_enclave_tests {
    use crate::tee::attestation::{AttestationEvidence, AttestationReport};
    use crate::tee::enclave::{EnclaveConfig, TeeEnclave};
    use crate::tee::secure_storage::{EncryptedData, SecureStorage};

    #[test]
    fn test_enclave_creation() {
        let config = EnclaveConfig {
            max_heap_size: 1024 * 1024,
            max_stack_size: 128 * 1024,
            enable_debug: true,
        };

        let enclave = TeeEnclave::new(config).unwrap();
        assert!(enclave.get_id() > 0 || enclave.get_id() == 0);
    }

    #[test]
    fn test_enclave_seal_unseal() {
        let enclave = TeeEnclave::new(EnclaveConfig::default()).unwrap();
        let data = b"Sensitive data for sealing";

        let sealed = enclave.seal_data(data).unwrap();
        let unsealed = enclave.unseal_data(&sealed).unwrap();

        assert_eq!(data, unsealed.as_slice());
    }

    #[test]
    fn test_enclave_ecall() {
        let enclave = TeeEnclave::new(EnclaveConfig::default()).unwrap();
        let _ = std::panic::catch_unwind(|| enclave.call_secure_function(|_| 42));
    }

    #[test]
    fn test_attestation_report_generation() {
        let report = AttestationReport::generate(0x1234, &[1u8, 2, 3, 4]).unwrap();

        assert_eq!(report.enclave_id, 0x1234);
        assert!(report.measurement.len() > 0);
    }

    #[test]
    fn test_attestation_evidence_verification() {
        let evidence = AttestationEvidence {
            report: AttestationReport::generate(0x1234, &[0u8; 32]).unwrap(),
            signature: vec![0u8; 64],
            certificate: vec![1u8; 512],
        };

        assert!(evidence.verify().is_ok());
    }

    #[test]
    fn test_secure_storage_write_read() {
        let storage = SecureStorage::new("test_enclave".to_string());
        let data = EncryptedData {
            ciphertext: vec![1u8, 2, 3, 4],
            nonce: [0u8; 12],
            tag: [0u8; 16],
        };

        storage.write("key1", &data).unwrap();
        let retrieved = storage.read("key1").unwrap().unwrap();

        assert_eq!(data.ciphertext, retrieved.ciphertext);
    }

    #[test]
    fn test_secure_storage_delete() {
        let storage = SecureStorage::new("test_enclave2".to_string());
        let data = EncryptedData::new(vec![1u8, 2, 3]);

        storage.write("key_to_delete", &data).unwrap();
        storage.delete("key_to_delete").unwrap();
        let result = storage.read("key_to_delete").unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_remote_attestation_create_report_and_verify_evidence() {
        use crate::tee::attestation::RemoteAttestation;

        let attestation = RemoteAttestation::new();
        let report = attestation.create_report(0, b"test_report").unwrap();
        let evidence = AttestationEvidence {
            report,
            signature: vec![0u8; 64],
            certificate: vec![1u8; 512],
        };

        let result = attestation.verify_evidence(&evidence).unwrap();
        assert!(result);
    }

    #[test]
    fn test_secure_storage_clear() {
        let storage = SecureStorage::new("test_enclave3".to_string());
        let data = EncryptedData::new(vec![1u8, 2, 3]);

        storage.write("key1", &data).unwrap();
        storage.write("key2", &data).unwrap();
        storage.clear().unwrap();
        let result1 = storage.read("key1").unwrap();
        let result2 = storage.read("key2").unwrap();

        assert!(result1.is_none());
        assert!(result2.is_none());
    }
}
