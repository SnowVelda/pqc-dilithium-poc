import oqs
import hashlib
import json
import time
import os
import glob

# --- Constants and Configuration ---
DILITHIUM_ALG = "Dilithium2" # Using Dilithium2 for this POC
WALLET_DIR = "wallets"
BLOCKCHAIN_FILE = "blockchain.json"
DIFFICULTY = 2 # For simplified Proof-of-Work

# Ensure wallet directory exists
os.makedirs(WALLET_DIR, exist_ok=True)

# --- Helper Functions ---
def generate_key_pair_dilithium():
    """Generates a Dilithium key pair using liboqs."""
    with oqs.Signature(DILITHIUM_ALG) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    return private_key, public_key

def save_key_pair(private_key, public_key, wallet_name):
    """Saves a Dilithium key pair to files."""
    priv_path = os.path.join(WALLET_DIR, f"{wallet_name}_priv.key")
    pub_path = os.path.join(WALLET_DIR, f"{wallet_name}_pub.key")
    with open(priv_path, "wb") as f:
        f.write(private_key)
    with open(pub_path, "wb") as f:
        f.write(public_key)
    print(f"Wallet '{wallet_name}' saved.")

def load_key_pair(wallet_name):
    """Loads a Dilithium key pair from files."""
    priv_path = os.path.join(WALLET_DIR, f"{wallet_name}_priv.key")
    pub_path = os.path.join(WALLET_DIR, f"{wallet_name}_pub.key")
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        return None, None
    with open(priv_path, "rb") as f:
        private_key = f.read()
    with open(pub_path, "rb") as f:
        public_key = f.read()
    return private_key, public_key

def get_available_wallets():
    """Returns a list of available wallet names."""
    return sorted(list(set([
        os.path.basename(f).replace('_priv.key', '').replace('_pub.key', '')
        for f in glob.glob(os.path.join(WALLET_DIR, "*.key"))
    ])))

# --- Transaction Class ---
class Transaction:
    def __init__(self, sender_public_key_hex, recipient_public_key_hex, amount, timestamp=None, signature_hex=None):
        self.sender = sender_public_key_hex
        self.recipient = recipient_public_key_hex
        self.amount = amount
        self.timestamp = timestamp or time.time()
        self.signature = signature_hex

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            sender_public_key_hex=data['sender'],
            recipient_public_key_hex=data['recipient'],
            amount=data['amount'],
            timestamp=data['timestamp'],
            signature_hex=data['signature']
        )

    def calculate_hash(self):
        """Calculates the SHA256 hash of the transaction data (excluding signature)."""
        transaction_data = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp
        }
        return hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode()).hexdigest()

    def sign(self, private_key_bytes):
        """Signs the transaction hash using the provided private key."""
        message_hash = self.calculate_hash().encode('utf-8')
        with oqs.Signature(DILITHIUM_ALG) as signer:
            signer.generate_keypair(private_key_bytes) # Load private key
            self.signature = signer.sign(message_hash).hex()
        print(f"Transaction signed by {self.sender[:8]}...")

    def verify_signature(self, public_key_bytes):
        """Verifies the transaction's signature using the provided public key."""
        if not self.signature:
            return False
        message_hash = self.calculate_hash().encode('utf-8')
        try:
            with oqs.Signature(DILITHIUM_ALG) as verifier:
                return verifier.verify(message_hash, bytes.fromhex(self.signature), public_key_bytes)
        except Exception as e:
            print(f"Error during signature verification: {e}")
            return False

# --- Block Class ---
class Block:
    def __init__(self, index, transactions, previous_hash, proof, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.transactions = [tx.to_dict() for tx in transactions] # Store as dicts
        self.previous_hash = previous_hash
        self.proof = proof
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA256 hash of the block content."""
        block_string = json.dumps(self.to_dict_no_hash(), sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict_no_hash(self):
        """Returns a dictionary representation of the block without its own hash."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "proof": self.proof
        }

    @classmethod
    def from_dict(cls, data):
        transactions = [Transaction.from_dict(tx_data) for tx_data in data['transactions']]
        block = cls(
            index=data['index'],
            transactions=transactions,
            previous_hash=data['previous_hash'],
            proof=data['proof'],
            timestamp=data['timestamp']
        )
        block.hash = data['hash'] # Re-add the hash after creation
        return block

# --- Blockchain Class ---
class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.load_chain()
        if not self.chain: # If no chain loaded, create genesis block
            self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the first block in the chain."""
        genesis_block = Block(index=0, transactions=[], previous_hash="0", proof=100)
        self.chain.append(genesis_block)
        self.save_chain()
        print("Genesis Block created.")

    @property
    def last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        """Adds a new transaction to the list of pending transactions."""
        if not transaction.sender or not transaction.recipient or transaction.amount <= 0:
            print("Invalid transaction data.")
            return False
        
        # Verify transaction signature before adding to pending
        sender_pub_key_bytes = bytes.fromhex(transaction.sender)
        if not transaction.verify_signature(sender_pub_key_bytes):
            print("Transaction signature verification failed. Not adding to pending.")
            return False

        self.pending_transactions.append(transaction)
        print(f"Transaction added to pending: {transaction.calculate_hash()[:8]}...")
        return True

    def proof_of_work(self, last_proof):
        """Simple Proof of Work algorithm: - Find a number p' such that hash(pp') contains leading zeros"""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        """Validates the proof: Does hash(last_proof, proof) contain DIFFICULTY leading zeros?"""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:DIFFICULTY] == "0" * DIFFICULTY

    def mine_block(self, miner_public_key_hex):
        """Mines a new block and adds it to the chain."""
        if not self.pending_transactions:
            print("No pending transactions to mine.")
            return None

        last_block = self.last_block
        proof = self.proof_of_work(last_block.proof)

        # Reward the miner with a transaction (simplified)
        # This transaction doesn't need to be signed by the miner, as it's a reward
        # from the system.
        coinbase_tx = Transaction(
            sender_public_key_hex="0" * 64, # System address
            recipient_public_key_hex=miner_public_key_hex,
            amount=1, # Mining reward
            signature_hex="0" * 128 # No signature for coinbase
        )
        # Add coinbase transaction to the beginning of the transactions to be mined
        transactions_to_mine = [coinbase_tx] + self.pending_transactions

        new_block = Block(
            index=last_block.index + 1,
            transactions=transactions_to_mine,
            previous_hash=last_block.hash,
            proof=proof
        )
        self.pending_transactions = []
        self.chain.append(new_block)
        self.save_chain()
        print(f"Block {new_block.index} mined by {miner_public_key_hex[:8]}... with hash: {new_block.hash[:8]}...")
        return new_block

    def is_chain_valid(self):
        """Verifies the integrity of the entire blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Check block hash
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {current_block.index}: Hash mismatch.")
                return False

            # Check previous hash link
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {current_block.index}: Previous hash mismatch.")
                return False

            # Check Proof of Work
            if not self.valid_proof(previous_block.proof, current_block.proof):
                print(f"Block {current_block.index}: Invalid Proof of Work.")
                return False

            # Verify all transactions in the block
            for tx_data in current_block.transactions:
                # Skip coinbase transaction verification
                if tx_data['sender'] == "0" * 64:
                    continue
                tx = Transaction.from_dict(tx_data)
                sender_pub_key_bytes = bytes.fromhex(tx.sender)
                if not tx.verify_signature(sender_pub_key_bytes):
                    print(f"Block {current_block.index}: Invalid signature in transaction {tx.calculate_hash()[:8]}...")
                    return False
        return True

    def save_chain(self):
        """Saves the blockchain to a JSON file."""
        with open(BLOCKCHAIN_FILE, "w") as f:
            # Convert Block objects to dicts for JSON serialization
            serializable_chain = [block.to_dict_no_hash() for block in self.chain]
            # Add the hash back for saving
            for i, block in enumerate(self.chain):
                serializable_chain[i]['hash'] = block.hash
            json.dump(serializable_chain, f, indent=4)
        print("Blockchain saved.")

    def load_chain(self):
        """Loads the blockchain from a JSON file."""
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, "r") as f:
                data = json.load(f)
                self.chain = [Block.from_dict(block_data) for block_data in data]
            print("Blockchain loaded.")
        else:
            print("No existing blockchain found.")

# --- CLI Functions ---
def create_wallet_cli():
    """CLI function to create a new Dilithium wallet."""
    wallet_name = input("Enter a name for your new wallet: ").strip()
    if not wallet_name:
        print("Wallet name cannot be empty.")
        return
    if os.path.exists(os.path.join(WALLET_DIR, f"{wallet_name}_priv.key")):
        print(f"Wallet '{wallet_name}' already exists.")
        return

    private_key, public_key = generate_key_pair_dilithium()
    save_key_pair(private_key, public_key, wallet_name)
    print(f"Wallet '{wallet_name}' created. Public Key: {public_key.hex()}")

def create_transaction_cli(blockchain):
    """CLI function to create and sign a new transaction."""
    wallets = get_available_wallets()
    if not wallets:
        print("No wallets found. Please create a wallet first.")
        return

    print("\nAvailable Wallets (Sender):")
    for i, wallet in enumerate(wallets):
        print(f"{i+1}. {wallet}")
    
    sender_choice = input("Select sender wallet by number: ").strip()
    try:
        sender_wallet_name = wallets[int(sender_choice) - 1]
    except (ValueError, IndexError):
        print("Invalid sender wallet choice.")
        return

    sender_priv_key, sender_pub_key = load_key_pair(sender_wallet_name)
    if not sender_priv_key:
        print(f"Could not load private key for {sender_wallet_name}.")
        return

    recipient_pub_key_hex = input("Enter recipient's public key (hex): ").strip()
    if not recipient_pub_key_hex:
        print("Recipient public key cannot be empty.")
        return
    try:
        # Basic validation for hex string
        bytes.fromhex(recipient_pub_key_hex)
    except ValueError:
        print("Invalid recipient public key format (must be hex).")
        return

    amount_str = input("Enter amount: ").strip()
    try:
        amount = float(amount_str)
        if amount <= 0:
            raise ValueError
    except ValueError:
        print("Invalid amount. Must be a positive number.")
        return

    tx = Transaction(sender_pub_key.hex(), recipient_pub_key_hex, amount)
    tx.sign(sender_priv_key)

    if blockchain.add_transaction(tx):
        print("Transaction successfully created, signed, and added to pending transactions.")
    else:
        print("Failed to add transaction.")

def mine_block_cli(blockchain):
    """CLI function to mine a new block."""
    wallets = get_available_wallets()
    if not wallets:
        print("No wallets found to receive mining reward. Please create a wallet first.")
        return

    print("\nAvailable Wallets (Miner):")
    for i, wallet in enumerate(wallets):
        print(f"{i+1}. {wallet}")
    
    miner_choice = input("Select miner wallet by number: ").strip()
    try:
        miner_wallet_name = wallets[int(miner_choice) - 1]
    except (ValueError, IndexError):
        print("Invalid miner wallet choice.")
        return
    
    _, miner_pub_key = load_key_pair(miner_wallet_name)
    if not miner_pub_key:
        print(f"Could not load public key for {miner_wallet_name}.")
        return

    print("Mining new block...")
    blockchain.mine_block(miner_pub_key.hex())

def verify_chain_cli(blockchain):
    """CLI function to verify the integrity of the blockchain."""
    print("\nVerifying blockchain integrity...")
    if blockchain.is_chain_valid():
        print("Blockchain is VALID!")
    else:
        print("Blockchain is INVALID!")

def view_chain_cli(blockchain):
    """CLI function to display the blockchain."""
    print("\n--- Current Blockchain ---")
    if not blockchain.chain:
        print("Blockchain is empty.")
        return
    for block in blockchain.chain:
        print(f"Block #{block.index}")
        print(f"  Timestamp: {time.ctime(block.timestamp)}")
        print(f"  Hash: {block.hash}")
        print(f"  Previous Hash: {block.previous_hash}")
        print(f"  Proof: {block.proof}")
        print("  Transactions:")
        if block.transactions:
            for tx in block.transactions:
                print(f"    - From: {tx['sender'][:8]}... To: {tx['recipient'][:8]}... Amount: {tx['amount']} Sig: {tx['signature'][:8]}...")
        else:
            print("    (No transactions)")
        print("-" * 30)

def view_pending_transactions_cli(blockchain):
    """CLI function to display pending transactions."""
    print("\n--- Pending Transactions ---")
    if not blockchain.pending_transactions:
        print("No pending transactions.")
        return
    for tx in blockchain.pending_transactions:
        print(f"  - From: {tx.sender[:8]}... To: {tx.recipient[:8]}... Amount: {tx.amount} Sig: {tx.signature[:8]}...")
    print("-" * 30)

def main_menu():
    """Main CLI menu for the PQC-Dilithium Blockchain POC."""
    blockchain = Blockchain()

    while True:
        print("\n--- PQC-Dilithium Blockchain POC Menu ---")
        print("1. Create New Wallet")
        print("2. Create New Transaction")
        print("3. Mine New Block")
        print("4. Verify Blockchain")
        print("5. View Blockchain")
        print("6. View Pending Transactions")
        print("7. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            create_wallet_cli()
        elif choice == '2':
            create_transaction_cli(blockchain)
        elif choice == '3':
            mine_block_cli(blockchain)
        elif choice == '4':
            verify_chain_cli(blockchain)
        elif choice == '5':
            view_chain_cli(blockchain)
        elif choice == '6':
            view_pending_transactions_cli(blockchain)
        elif choice == '7':
            print("Exiting PQC-Dilithium Blockchain POC. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main_menu()
    except ImportError:
        print("\nError: 'oqs' library not found.")
        print("Please install liboqs-python: pip install liboqs-python")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
