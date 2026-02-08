# GEMINI.md: ZK Rollup with RISC-V and TEE

This document provides a comprehensive overview of the `zk-rollup` project,
intended to be used as a context file for AI-assisted development.

## Project Overview

This is an experimental Rust-based project implementing a Zero-Knowledge (ZK) Rollup.
It has a strong focus on leveraging low-level hardware optimizations,
specifically for the RISC-V architecture, and incorporates a Trusted Execution
Environment (TEE) for enhanced security.

### Core Technologies

* **Language:** Rust (2024 Edition)
* **Cryptography:**
  * Zero-Knowledge Proofs: Groth16 for proof generation and verification.
  * Symmetric Encryption: AES-256
  * Hashing: SHA-256
  * Asymmetric Cryptography: Ed25519 for digital signatures.
* **Hardware Acceleration:** The cryptographic operations are designed to be
  accelerated by a RISC-V crypto extension (though currently using a software
  mock).
* **Security:** A TEE (Trusted Execution Environment) layer provides a secure
  enclave for sensitive operations like key management and transaction
  processing.

### Architecture

The project is structured into three main modules:

1. `src/crypto`: Contains all cryptographic primitives. Each primitive has a
   `Riscv` suffixed struct (e.g., `Aes256Riscv`) that abstracts away the
   hardware acceleration.
2. `src/rollup`: Implements the core ZK Rollup logic. This includes state
   management (accounts, balances, Merkle trees), transaction handling, and the
   ZK proof system.
3. `src/tee`: Provides the TEE functionality. This includes enclave management,
   remote attestation, and secure storage.

The `src/main.rs` file serves as the main entry point and contains a series of
tests to demonstrate the functionality of each module.

## Building and Running

### Dependencies

* Rust 2024 Edition
* Using cargo add to manage dependencies
* `cargo` for building and testing.

### Commands

* **Check:** `cargo check`
* **Build (Debug):** `cargo build`
* **Build (Release):** `cargo build --release`
* **Run all tests:** `cargo test`
* **Run main application (which runs integration tests):** `cargo run`

## Development Conventions

* **Error Handling:** The project uses the `thiserror` crate for custom error
  types. Errors are generally propagated up using `Result<T, Box<dyn Error>>`.
* **Naming:** Structs that leverage the (mocked) RISC-V hardware acceleration
  are suffixed with `Riscv` (e.g., `Aes256Riscv`).
* **Testing:** Unit and integration tests are included within the source code.
  The main entry point (`src/main.rs`) is used to run a series of high-level
  integration tests. Tests for specific modules are in files like `*_tests.rs`.
* **Documentation:** The code is well-documented with Rustdoc comments,
  explaining the purpose of modules, structs, and functions.

## Key Files

* `README.md`: The primary source of human-readable documentation.
* `Cargo.toml`: Defines project metadata and dependencies.
* `src/main.rs`: The main application entry point, which runs a sequence of
  tests demonstrating the project's features.
* `src/crypto/mod.rs`: The root module for all cryptographic operations.
  * `src/crypto/aes.rs`: AES-256 encryption.
  * `src/crypto/sha256.rs`: SHA-256 hashing.
  * `src/crypto/ec.rs`: Ed25519 signatures.
  * `src/crypto/riscv_ext.rs`: The trait and mock implementation for the RISC-V
    crypto hardware accelerator.
* `src/rollup/mod.rs`: The root module for the Rollup logic.
  * `src/rollup/state.rs`: Manages the Rollup's state, including accounts and
    the Merkle tree.
  * `src/rollup/transaction.rs`: Defines transaction types.
  * `src/rollup/zk_proof.rs`: Handles ZK proof generation and verification using
    Groth16.
* `src/tee/mod.rs`: The root module for the Trusted Execution Environment.
  * `src/tee/enclave.rs`: Manages the TEE enclave lifecycle.
  * `src/tee/attestation.rs`: Handles remote attestation.
  * `src/tee/secure_storage.rs`: Provides secure, encrypted storage within the
    enclave.
