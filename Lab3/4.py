# Design and implement a secure file transfer system using RSA (2048-bit) and ECC (secp256r1
# curve) public key algorithms. Generate and exchange keys, then encrypt and decrypt files of
# varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and compare the
# performance in terms of key generation time, encryption/decryption speed, and computational
# overhead. Evaluate the security and efficiency of each algorithm in the context of file transfer,
# considering factors such as key size, storage requirements, and resistance to known attacks.
# Document your findings, including performance metrics and a summary of the strengths and
# weaknesses of RSA and ECC for secure file transfer.
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    """Generate RSA keys."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def generate_ecc_keys():
    """Generate ECC keys."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, data):
    """Encrypt data using RSA."""
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def decrypt_rsa(private_key, ciphertext):
    """Decrypt data using RSA."""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext)

def encrypt_aes(key, data):
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_aes(key, ciphertext):
    """Decrypt data using AES."""
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def measure_performance():
    # File size configuration
    file_sizes = [1 * 1024 * 1024, 10 * 1024 * 1024]  # 1MB and 10MB

    # RSA Key Generation
    start_time = time.time()
    rsa_private, rsa_public = generate_rsa_keys()
    rsa_keygen_time = time.time() - start_time

    # ECC Key Generation
    start_time = time.time()
    ecc_private, ecc_public = generate_ecc_keys()
    ecc_keygen_time = time.time() - start_time

    results = []

    for size in file_sizes:
        # Generate dummy data
        data = os.urandom(size)

        # Generate AES key
        aes_key = get_random_bytes(16)  # AES-128

        # Encrypt data with AES
        start_time = time.time()
        aes_encrypted = encrypt_aes(aes_key, data)
        aes_encrypt_time = time.time() - start_time

        # Encrypt AES key with RSA
        start_time = time.time()
        rsa_encrypted_key = encrypt_rsa(rsa_public, aes_key)
        rsa_encrypt_key_time = time.time() - start_time

        # Decrypt AES key with RSA
        start_time = time.time()
        decrypted_aes_key = decrypt_rsa(rsa_private, rsa_encrypted_key)
        rsa_decrypt_key_time = time.time() - start_time

        # Decrypt data with AES
        start_time = time.time()
        aes_decrypted = decrypt_aes(decrypted_aes_key, aes_encrypted)
        aes_decrypt_time = time.time() - start_time

        # Performance metrics
        results.append({
            'size': size,
            'rsa_keygen_time': rsa_keygen_time,
            'ecc_keygen_time': ecc_keygen_time,
            'aes_encrypt_time': aes_encrypt_time,
            'rsa_encrypt_key_time': rsa_encrypt_key_time,
            'rsa_decrypt_key_time': rsa_decrypt_key_time,
            'aes_decrypt_time': aes_decrypt_time,
            'data_matches': data == aes_decrypted,
        })

    return results

def main():
    performance_results = measure_performance()

    for result in performance_results:
        print(f"File Size: {result['size'] / (1024 * 1024)} MB")
        print(f"RSA Key Generation Time: {result['rsa_keygen_time']:.6f} seconds")
        print(f"ECC Key Generation Time: {result['ecc_keygen_time']:.6f} seconds")
        print(f"AES Encryption Time: {result['aes_encrypt_time']:.6f} seconds")
        print(f"RSA Encrypt AES Key Time: {result['rsa_encrypt_key_time']:.6f} seconds")
        print(f"RSA Decrypt AES Key Time: {result['rsa_decrypt_key_time']:.6f} seconds")
        print(f"AES Decryption Time: {result['aes_decrypt_time']:.6f} seconds")
        print(f"Data Matches: {result['data_matches']}")
        print("-" * 40)

if __name__ == "__main__":
    main()
