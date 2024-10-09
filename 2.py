# Try using the Diffie-Hellman asymmetric encryption standard and verify
# the above steps.
import random
from sympy import mod_inverse, isprime
import sympy

def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p


def genkeypair(bits=16):
    """ Generate RSA public and private key pair. """
    p = genprime(bits)
    q = genprime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(2, phi_n - 1)
    while sympy.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)

    return (n, e), (n, d)  # Public key and private key


def encrypt(pubkey, plaintext):
    """ Encrypt a plaintext message using the public key. """
    n, e = pubkey
    return pow(plaintext, e, n)


def decrypt(privkey, ciphertext):
    """ Decrypt a ciphertext message using the private key. """
    n, d = privkey
    return pow(ciphertext, d, n)


def homomorphic_multiply(c1, c2, n):
    """ Multiply two ciphertexts under RSA encryption. """
    return (c1 * c2) % n


# Example usage
if __name__ == "__main__":
    num1 = 7
    num2 = 3

    pubkey, privkey = genkeypair()

    # Encrypt the numbers
    c1 = encrypt(pubkey, num1)
    c2 = encrypt(pubkey, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    # Perform homomorphic multiplication
    c_product = homomorphic_multiply(c1, c2, pubkey[0])
    print(f"Encrypted product: {c_product}")

    # Decrypt the result
    dec_product = decrypt(privkey, c_product)
    print(f"Decrypted product: {dec_product}")

    # Verify the result
    print(f"Original product: {num1 * num2}")
