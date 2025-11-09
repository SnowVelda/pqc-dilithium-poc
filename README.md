# PQC-Dilithium Blockchain Proof-of-Concept (POC) using `liboqs-python`

This project is a Proof-of-Concept (POC) demonstrating the application of CRYSTALS-Dilithium post-quantum digital signatures within a simplified blockchain framework. It leverages the `liboqs-python` library, which provides Python bindings to the Open Quantum Safe (OQS) project's C implementations of post-quantum cryptographic algorithms.

## Purpose

The primary purpose of this POC is to illustrate how post-quantum digital signatures can secure a distributed ledger (blockchain). Specifically, it demonstrates:

1.  **Post-Quantum Wallets**: Generating and managing key pairs using CRYSTALS-Dilithium.
2.  **Signed Transactions**: Creating and signing transactions with Dilithium, ensuring their authenticity and integrity.
3.  **Blockchain Integrity**: How these signed transactions are incorporated into blocks, and how the entire chain's integrity (including transaction validity) can be verified.
4.  **Proof-of-Work**: A basic mechanism to secure the chain against tampering.

This POC aims to provide a tangible example of post-quantum cryptography in action, moving beyond isolated cryptographic operations to a more integrated system.

## Features

*   **Wallet Management**: Create and load Dilithium key pairs.
*   **Transaction Creation**: Define sender, recipient, and amount, then sign with the sender's private key.
*   **Block Mining**: Group pending transactions into a new block, solve a simple Proof-of-Work puzzle, and add it to the chain. Includes a mining reward.
*   **Blockchain Verification**: Validate the entire chain's hashes, Proof-of-Work, and all transaction signatures.
*   **Persistence**: The blockchain state and wallets are saved to local files (`blockchain.json`, `wallets/`).

## How to Run

1.  **Ensure Python is installed.** (Python 3.8+ recommended)

2.  **Install `liboqs-python`:**
    It is highly recommended to use a Python virtual environment.
    ```bash
    # Create a virtual environment
    python -m venv venv

    # Activate the virtual environment
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    # source venv/bin/activate

    # Install liboqs-python
    pip install liboqs-python
    ```
    *Note: `liboqs-python` may require compilation of native code, which might necessitate build tools (e.g., C/C++ compiler) on your system. Refer to the `liboqs-python` documentation for specific build requirements if you encounter issues.*

3.  **Navigate to this project directory** in your terminal:
    ```bash
    cd pqc_dilithium_implementation
    ```

4.  **Run the Python script:**
    ```bash
    python dilithium_poc.py
    ```
    This will launch an interactive command-line interface.

## Usage Examples (from the CLI menu)

1.  **Create Wallets:**
    *   Choose option `1`.
    *   Enter names like `Alice`, `Bob`, `Miner1`.
    *   This will generate Dilithium key pairs and save them in the `wallets/` directory.

2.  **Create Transactions:**
    *   Choose option `2`.
    *   Select a sender wallet (e.g., `Alice`).
    *   Enter a recipient's public key (you can get this from another wallet's `.key` file or by creating another wallet and copying its public key output).
    *   Enter an amount.
    *   The transaction will be signed by Alice's private key and added to pending transactions.

3.  **Mine Blocks:**
    *   Choose option `3`.
    *   Select a miner wallet (e.g., `Miner1`).
    *   The system will perform Proof-of-Work, collect pending transactions (including a reward for `Miner1`), and add a new block to the chain.

4.  **Verify Blockchain:**
    *   Choose option `4`.
    *   The system will check all block hashes, Proof-of-Work, and every transaction's Dilithium signature for integrity.

5.  **View Blockchain/Pending Transactions:**
    *   Options `5` and `6` allow you to inspect the current state of the ledger and any unmined transactions.

## Disclaimer

While this POC uses `liboqs-python`, a library that implements standardized post-quantum cryptographic algorithms, this specific demonstration code is still for **educational and illustrative purposes only**. It is not designed for production environments and may lack robust error handling, secure key management, network consensus mechanisms, or other features critical for real-world blockchain and cryptographic applications. Always consult with cryptographic experts and follow best practices for any security-sensitive deployments.
