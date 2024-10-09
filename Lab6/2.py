import random
from sympy import isprime
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

def generate_prime(bits=256):
    """Generate a prime number of specified bit length."""
    while True:
        prime = random.getrandbits(bits)
        if isprime(prime):
            return prime

def diffie_hellman_key_exchange(p, g, private_key):
    """Compute the public key in Diffie-Hellman."""
    return pow(g, private_key, p)

def compute_shared_secret(public_key, private_key, p):
    """Compute the shared secret using Diffie-Hellman."""
    return pow(public_key, private_key, p)

def derive_key(shared_secret):
    """Derive a key from the shared secret using HMAC."""
    # Convert the shared secret to bytes (make sure it's large enough)
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    return HMAC.new(shared_secret_bytes, digestmod=SHA256).digest()

def sign_message(message, key):
    """Sign a message using HMAC."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    return h.digest()

def verify_signature(message, signature, key):
    """Verify an HMAC signature."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    try:
        h.verify(signature)
        return True
    except ValueError:
        return False

# Example usage
if __name__ == "__main__":
    bits = 256

    # Generate a prime number and a base (generator)
    p = generate_prime(bits)
    g = random.randint(2, p - 1)

    # Alice's private and public keys
    alice_private = random.randint(1, p - 2)
    alice_public = diffie_hellman_key_exchange(p, g, alice_private)

    # Bob's private and public keys
    bob_private = random.randint(1, p - 2)
    bob_public = diffie_hellman_key_exchange(p, g, bob_private)

    # Compute shared secrets
    alice_shared = compute_shared_secret(bob_public, alice_private, p)
    bob_shared = compute_shared_secret(alice_public, bob_private, p)

    # Derive key from shared secret
    key = derive_key(alice_shared)

    # Sign and verify a message
    message = b"Secret message"
    signature = sign_message(message, key)
    is_valid = verify_signature(message, signature, key)

    # Output results
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print(f"Alice's private key: {alice_private}")
    print(f"Alice's public key: {alice_public}")
    print(f"Bob's private key: {bob_private}")
    print(f"Bob's public key: {bob_public}")
    print(f"Alice's shared secret: {alice_shared}")
    print(f"Bob's shared secret: {bob_shared}")
    print("Shared secrets match: {}".format(alice_shared == bob_shared))
    print(f"Message: {message}")
    print(f"Signature: {signature.hex()}")
    print(f"Signature Valid: {is_valid}")
