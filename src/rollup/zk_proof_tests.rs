#[cfg(test)]
mod zk_proof_tests {
    use crate::rollup::state::{Account, Balance, RollupState};
    use crate::rollup::transaction::{Transaction, TransferTx};
    use crate::rollup::zk_proof::{Proof, PublicInput, ZKGroth16};

    #[test]
    fn test_zkgroth16_proof_generation() {
        let mut groth16 = ZKGroth16::new();

        let witness = vec![1u8; 32];
        let proof = groth16.generate_proof(&witness).unwrap();

        assert_eq!(proof.pi_a.len(), 3);
        assert_eq!(proof.pi_b.len(), 6);
        assert_eq!(proof.pi_c.len(), 2);
    }

    #[test]
    fn test_zkgroth16_proof_verification() {
        let mut groth16 = ZKGroth16::new();
        let vk = groth16.setup();

        let witness = vec![1u8; 32];
        let proof = groth16.generate_proof(&witness).unwrap();

        let public_input = PublicInput::from_witness(&witness);
        let valid = groth16.verify(&vk, &proof, &public_input).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_zkgroth16_proof_serialization() {
        let mut groth16 = ZKGroth16::new();
        let witness = vec![5u8; 32];
        let proof = groth16.generate_proof(&witness).unwrap();

        let serialized = bincode::serialize(&proof).unwrap();
        let deserialized: Proof = bincode::deserialize(&serialized).unwrap();

        assert_eq!(proof.pi_a, deserialized.pi_a);
    }

    #[test]
    fn test_msm_acceleration() {
        let groth16 = ZKGroth16::new();
        let points: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 32]).collect();
        let scalars: Vec<Vec<u8>> = (0..10).map(|i| vec![(i + 1) as u8; 32]).collect();

        let result = groth16.accelerated_msm(&points, &scalars).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_rollup_state_account_creation() {
        let mut state = RollupState::new();

        let account = Account {
            id: 0,
            public_key: vec![1u8; 32],
            nonce: 0,
            balance: Balance::new(),
        };

        let id = state.create_account(account).unwrap();
        assert_eq!(id, 0);
        assert!(state.get_account(0).is_some());
    }

    #[test]
    fn test_rollup_state_balance_update() {
        let mut state = RollupState::new();
        let account = Account {
            id: 0,
            public_key: vec![1u8; 32],
            nonce: 0,
            balance: Balance::new(),
        };
        state.create_account(account).unwrap();

        state.update_balance(0, 100).unwrap();
        let account = state.get_account(0).unwrap();
        assert_eq!(account.balance.eth, 100);
    }

    #[test]
    fn test_rollup_state_transfer() {
        use crate::crypto::ec::Ed25519Riscv;

        let mut state = RollupState::new();

        let ed25519 = Ed25519Riscv::new();
        let (secret_key, public_key) = ed25519.keygen();

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

        let mut tx = TransferTx {
            from: 0,
            to: 1,
            amount: 100,
            nonce: 0,
            signature: vec![0u8; 64],
        };

        tx.sign(&secret_key).unwrap();

        state.apply_transfer(&tx).unwrap();

        let acc1 = state.get_account(0).unwrap();
        let acc2 = state.get_account(1).unwrap();

        assert_eq!(acc1.balance.eth, 900);
        assert_eq!(acc2.balance.eth, 100);
    }

    #[test]
    fn test_rollup_state_merkle_root() {
        let mut state = RollupState::new();

        for i in 0..4 {
            let account = Account {
                id: i,
                public_key: vec![i as u8; 32],
                nonce: 0,
                balance: Balance::new(),
            };
            state.create_account(account).unwrap();
        }

        let root = state.get_merkle_root().unwrap();
        assert_eq!(root.len(), 32);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::Transfer(TransferTx {
            from: 1,
            to: 2,
            amount: 50,
            nonce: 1,
            signature: vec![9u8; 64],
        });

        let serialized = bincode::serialize(&tx).unwrap();
        let deserialized: Transaction = bincode::deserialize(&serialized).unwrap();

        match (tx, deserialized) {
            (Transaction::Transfer(t1), Transaction::Transfer(t2)) => {
                assert_eq!(t1.from, t2.from);
                assert_eq!(t1.amount, t2.amount);
            }
        }
    }

    #[test]
    fn test_get_account_by_key() {
        let mut state = RollupState::new();
        let public_key = vec![1u8; 32];
        let account = Account {
            id: 0,
            public_key: public_key.clone(),
            nonce: 0,
            balance: Balance::new(),
        };
        state.create_account(account).unwrap();

        let found_account = state.get_account_by_key(&public_key).unwrap();
        assert_eq!(found_account.id, 0);
    }

    #[test]
    fn test_get_account_count() {
        let mut state = RollupState::new();
        assert_eq!(state.get_account_count(), 0);

        let account = Account {
            id: 0,
            public_key: vec![1u8; 32],
            nonce: 0,
            balance: Balance::new(),
        };
        state.create_account(account).unwrap();
        assert_eq!(state.get_account_count(), 1);
    }

    #[test]
    fn test_transaction_builder() {
        use crate::rollup::transaction::TransactionBuilder;

        let tx = TransactionBuilder::new()
            .from(1)
            .to(2)
            .amount(100)
            .nonce(1)
            .build()
            .unwrap();

        assert_eq!(tx.get_sender(), Some(1));
        assert_eq!(tx.get_nonce(), 1);

        let Transaction::Transfer(transfer) = tx;
        assert_eq!(transfer.to, 2);
        assert_eq!(transfer.amount, 100);
        assert!(transfer.signature_bytes().is_some());
    }

    #[test]
    fn test_accelerated_fft() {
        let groth16 = ZKGroth16::new();
        let data: Vec<Vec<u8>> = (0..256).map(|i| vec![i as u8, 0, 0, 0]).collect();
        let result = groth16.accelerated_fft(&data, false).unwrap();
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn test_accelerated_polynomial_ops() {
        let groth16 = ZKGroth16::new();
        let poly_a: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8, 0, 0, 0]).collect();
        let poly_b: Vec<Vec<u8>> = (16..32).map(|i| vec![i as u8, 0, 0, 0]).collect();
        let result = groth16.accelerated_polynomial_ops(&poly_a, &poly_b).unwrap();
        assert_eq!(result.len(), 31); // (n-1) + (m-1) + 1 = 15+15+1 = 31
    }
}
