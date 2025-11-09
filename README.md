# PQC-Dilithium Proof-of-Concept (POC) using `liboqs-python`

This directory contains a Proof-of-Concept (POC) implementation demonstrating operations inspired by the CRYSTALS-Dilithium post-quantum digital signature algorithm. This POC now leverages the `liboqs-python` library, which provides Python bindings to the Open Quantum Safe (OQS) project's C implementations of post-quantum cryptographic algorithms.

## Purpose

The primary purpose of this POC is to illustrate the *flow* and *concepts* behind a digital signature scheme like Dilithium, including:

1.  **Key Generation**: Creating a public and private key pair using a real Dilithium implementation.
2.  **Signing**: Generating a signature for a given message using the private key.
3.  **Verification**: Checking the validity of a signature for a message using the public key.

By using `liboqs-python`, this POC moves beyond a purely conceptual (and insecure) implementation to demonstrate actual cryptographic operations as defined by the CRYSTALS-Dilithium algorithm.

## How to Run

1.  **Ensure Python is installed.**
2.  **Install `liboqs-python`:**
    It is highly recommended to use a Python virtual environment.
    ```bash
    python -m venv venv
    .\venv\Scripts\activate   # On Windows
    # source venv/bin/activate # On macOS/Linux
    pip install liboqs-python
    ```
    *Note: `liboqs-python` may require compilation of native code, which might necessitate build tools (e.g., C/C++ compiler) on your system.*
3.  **Navigate to this directory** in your terminal:
    ```bash
    cd pqc_dilithium_implementation
    ```
4.  **Run the Python script:**
    ```bash
    python dilithium_poc.py
    ```

## Disclaimer

While this POC uses `liboqs-python`, a library that implements standardized post-quantum cryptographic algorithms, this specific demonstration code is still for **educational and illustrative purposes only**. It is not designed for production environments and may lack robust error handling, secure key management, or other features critical for real-world cryptographic applications. Always consult with cryptographic experts and follow best practices for any security-sensitive deployments.