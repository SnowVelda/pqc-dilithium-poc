# PQC-Dilithium Proof-of-Concept (POC)

This directory contains a highly simplified, conceptual Proof-of-Concept (POC) implementation of operations inspired by the CRYSTALS-Dilithium post-quantum digital signature algorithm.

**WARNING: This implementation is NOT cryptographically secure and should NOT be used for any real-world applications or production environments.**

## Purpose

The primary purpose of this POC is to illustrate the *flow* and *concepts* behind a digital signature scheme like Dilithium, including:

1.  **Key Generation**: Creating a public and private key pair.
2.  **Signing**: Generating a signature for a given message using the private key.
3.  **Verification**: Checking the validity of a signature for a message using the public key.

Due to the mathematical complexity of CRYSTALS-Dilithium, this POC uses vastly simplified operations (e.g., hashing with random bytes) instead of the actual polynomial arithmetic over finite fields. Therefore, it does not provide any cryptographic security guarantees.

## How to Run

1.  Ensure you have Python installed.
2.  Navigate to this directory in your terminal.
3.  Run the Python script:
    ```bash
    python dilithium_poc.py
    ```

## Disclaimer

This code is for educational and illustrative purposes only. It does not implement the actual CRYSTALS-Dilithium algorithm securely or correctly. Using this code for any security-sensitive application is strongly discouraged and will lead to severe vulnerabilities.
