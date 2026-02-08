
#[cfg(test)]
mod hash_tests {
    use crate::crypto::hash::*;

    #[test]
    fn test_double_sha256() {
        let data = b"hello world";
        let hash = double_sha256(data);
        assert_eq!(hash.len(), 32);
        // Test against a known value if available
    }

    #[test]
    fn test_hash_combine() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let combined = hash_combine(&a, &b);
        assert_eq!(combined.len(), 32);
        assert_ne!(combined, a);
        assert_ne!(combined, b);
    }

    #[test]
    fn test_merkle_leaf() {
        let data = b"leaf";
        let leaf_hash = merkle_leaf(data);
        assert_eq!(leaf_hash.len(), 32);
    }

    #[test]
    fn test_merkle_branch() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let branch_hash = merkle_branch(&left, &right);
        assert_eq!(branch_hash.len(), 32);
    }

    #[test]
    fn test_calculate_merkle_root() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let root = calculate_merkle_root(&leaves);
        assert_eq!(root.len(), 32);
    }
}
