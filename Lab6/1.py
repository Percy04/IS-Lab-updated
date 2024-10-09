import random
from sympy import isprime, mod_inverse, gcd

def generate_prime(bits=512):
    """Generate a prime number of specified bit length."""
    while True:
        prime = random.getrandbits(bits)
        if isprime(prime):
            return prime

def generate_keys(bits=512):
    """Generate ElGamal public and private keys."""
    p = generate_prime(bits)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)  # y = g^x mod p
    
    private_key = (p, g, x)
    public_key = (p, g, y)
    return private_key, public_key

def sign_message(message, private_key):
    """Sign a message using the ElGamal private key."""
    p, g, x = private_key
    while True:
        k = random.randint(1, p - 2)  # Random integer k
        if gcd(k, p - 1) == 1:  # Ensure k is coprime to p-1
            break

    r = pow(g, k, p)  # r = g^k mod p
    k_inv = mod_inverse(k, p - 1)
    h = int.from_bytes(hash(message.encode()), byteorder='big') % p
    s = (k_inv * (h - x * r)) % (p - 1)
    
    return (r, s)

def verify_signature(message, signature, public_key):
    """Verify the ElGamal signature."""
    p, g, y = public_key
    r, s = signature
    h = int.from_bytes(hash(message.encode()), byteorder='big') % p
    
    v1 = pow(y, r, p) * pow(r, s, p) % p
    v2 = pow(g, h, p)
    
    return v1 == v2

def hash(message):
    """Simple hash function."""
    import hashlib
    return hashlib.sha256(message).digest()

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()
    
    # Message to sign
    message = "ElGamal Digital Signature Example"
    
    # Sign the message
    signature = sign_message(message, private_key)
    
    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    
    print(f"Message: {message}")
    print(f"Signature: {signature}")
    print(f"Signature valid: {is_valid}")
