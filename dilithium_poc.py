import oqs
import os

def run_dilithium_poc():
    """
    Demonstrates CRYSTALS-Dilithium key generation, signing, and verification
    using the liboqs-python library.
    """
    print("--- CRYSTALS-Dilithium Post-Quantum Signature POC (using liboqs-python) ---")
    print("WARNING: This POC uses a real cryptographic library but is for demonstration purposes only.")
    print("         Ensure proper security practices for production use.")

    # 1. Choose a Dilithium algorithm
    # liboqs supports various Dilithium parameter sets (e.g., Dilithium2, Dilithium3, Dilithium5)
    # We'll use Dilithium2 for this example.
    # You can list available algorithms with oqs.Signature.get_supported_signatures()
    dilithium_alg = "Dilithium2"

    if dilithium_alg not in oqs.Signature.get_supported_signatures():
        print(f"Error: {dilithium_alg} not supported by liboqs. Please check your liboqs installation.")
        return

    print(f"\nUsing Dilithium algorithm: {dilithium_alg}")

    # 2. Key Generation
    # Create a Signature object for the chosen algorithm
    with oqs.Signature(dilithium_alg) as signer:
        print("\nGenerating Dilithium key pair...")
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key() # Export the private key bytes

        print(f"Public Key (hex, first 32 bytes): {public_key[:32].hex()}...")
        print(f"Private Key (hex, first 32 bytes): {private_key[:32].hex()}...")

        # 3. Signing a message
        message_to_sign = b"This is a secret message to be signed by Dilithium."
        print(f"\nMessage to sign: {message_to_sign.decode()}")

        print("Signing message...")
        signature = signer.sign(message_to_sign)
        print(f"Signature (hex, first 32 bytes): {signature[:32].hex()}...")

        # 4. Verification
        print("\nVerifying signature with correct message and public key...")
        is_valid = signer.verify(message_to_sign, signature, public_key)
        print(f"Signature is valid: {is_valid}")

        # Test with tampered message
        print("\nAttempting verification with tampered message...")
        tampered_message = b"This is a tampered message."
        is_valid_tampered = signer.verify(tampered_message, signature, public_key)
        print(f"Signature is valid with tampered message: {is_valid_tampered}")

        # Test with tampered signature (by modifying a byte)
        print("\nAttempting verification with tampered signature...")
        if len(signature) > 0:
            tampered_signature = bytearray(signature)
            tampered_signature[0] = (tampered_signature[0] + 1) % 256 # Flip a byte
            is_valid_tampered_sig = signer.verify(message_to_sign, bytes(tampered_signature), public_key)
            print(f"Signature is valid with tampered signature: {is_valid_tampered_sig}")
        else:
            print("Cannot tamper with an empty signature.")

if __name__ == "__main__":
    try:
        run_dilithium_poc()
    except ImportError:
        print("\nError: 'oqs' library not found.")
        print("Please install liboqs-python: pip install liboqs-python")
    except Exception as e:
        print(f"\nAn error occurred: {e}")