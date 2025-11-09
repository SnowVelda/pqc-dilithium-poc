import hashlib
import os

class DilithiumPOC:
    def __init__(self, security_param=32):
        """
        A highly simplified Proof-of-Concept for Dilithium-like operations.
        NOT cryptographically secure. Do NOT use for any real-world applications.
        This is purely for demonstrating the *concept* of key generation, signing,
        and verification in a post-quantum signature scheme.
        """
        self.security_param = security_param

    def generate_keys(self):
        """
        Generates a public and private key pair.
        In a real Dilithium scheme, this involves polynomial arithmetic over finite fields.
        Here, we use simple random bytes for illustration.
        """
        private_key = os.urandom(self.security_param * 2) # Simplified: just random bytes
        public_key = hashlib.sha256(private_key).digest() # Simplified: public key derived from private key hash
        print(f"Generated Private Key (hex): {private_key.hex()}")
        print(f"Generated Public Key (hex): {public_key.hex()}")
        return private_key, public_key

    def sign_message(self, private_key, message):
        """
        Signs a message using the private key.
        In a real Dilithium scheme, this involves complex interactions between
        the message, private key polynomials, and random challenges.
        Here, we simply hash the message with the private key.
        """
        if not private_key:
            raise ValueError("Private key is required for signing.")
        
        combined = private_key + message.encode('utf-8')
        signature = hashlib.sha256(combined).digest() # Simplified: hash of private key + message
        print(f"Message: {message}")
        print(f"Generated Signature (hex): {signature.hex()}")
        return signature

    def verify_signature(self, public_key, message, signature):
        """
        Verifies a signature using the public key.
        In a real Dilithium scheme, this involves reconstructing a commitment
        and checking it against the public key and signature.
        Here, we re-derive the expected public key from a hypothetical private key
        (which is not how it works in reality) and compare hashes.
        This is the most abstract part and highlights the POC nature.
        """
        if not public_key or not signature:
            raise ValueError("Public key and signature are required for verification.")

        print("WARNING: DilithiumPOC verification is a placeholder and NOT cryptographically sound.")
        print("It merely demonstrates the *existence* of a verification step.")
        
        # For this POC, I will simulate a successful verification if the signature
        # matches a re-hashed value of the public key and message.
        # This is a *very* loose analogy to how a public key is used.
        expected_signature = hashlib.sha256(public_key + message.encode('utf-8')).digest()
        is_valid = (signature == expected_signature)
        print(f"Verification result (POC): {is_valid}")
        return is_valid

if __name__ == "__main__":
    dilithium = DilithiumPOC()

    # 1. Key Generation
    private_key, public_key = dilithium.generate_keys()

    # 2. Signing a message
    message_to_sign = "Hello, quantum world!"
    signature = dilithium.sign_message(private_key, message_to_sign)

    # 3. Verification
    print("\nAttempting verification with correct message and signature:")
    is_valid = dilithium.verify_signature(public_key, message_to_sign, signature)
    print(f"Signature is valid: {is_valid}")

    # Test with tampered message
    print("\nAttempting verification with tampered message:")
    tampered_message = "Hello, tampered world!"
    is_valid_tampered = dilithium.verify_signature(public_key, tampered_message, signature)
    print(f"Signature is valid with tampered message: {is_valid_tampered}")

    # Test with tampered signature (by creating a new one with a different private key)
    print("\nAttempting verification with tampered signature:")
    _, another_public_key = dilithium.generate_keys() # Generate a different key pair
    tampered_signature = dilithium.sign_message(private_key, message_to_sign + "tamper") # A different signature
    is_valid_tampered_sig = dilithium.verify_signature(public_key, message_to_sign, tampered_signature)
    print(f"Signature is valid with tampered signature: {is_valid_tampered_sig}")
