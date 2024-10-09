# Design and implement a secure file transfer system using RSA (2048-bit) and ECC (secp256r1
# curve) public key algorithms. Generate and exchange keys, then encrypt and decrypt files of
# varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and compare the
# performance in terms of key generation time, encryption/decryption speed, and computational
# overhead. Evaluate the security and efficiency of each algorithm in the context of file transfer,
# considering factors such as key size, storage requirements, and resistance to known attacks.
# Document your findings, including performance metrics and a summary of the strengths and
# weaknesses of RSA and ECC for secure file transfer.
import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RSA Key Generation (2048-bit)
def generate_rsa_keys():
    start_time = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    keygen_time = time.time() - start_time
    return private_key, public_key, keygen_time

# ECC Key Generation (secp256r1)
def generate_ecc_keys():
    start_time = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    keygen_time = time.time() - start_time
    return private_key, public_key, keygen_time

# AES key generation
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

# AES file encryption
def encrypt_file(file_data, aes_key):
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return iv, ciphertext

# AES file decryption
def decrypt_file(iv, ciphertext, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

# RSA encryption of AES key
def rsa_encrypt_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# RSA decryption of AES key
def rsa_decrypt_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ECC encryption of AES key (using ECDH shared secret)
def ecc_encrypt_key(aes_key, public_key):
    shared_key = ecc_private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
    return derived_key

# ECC decryption of AES key (using ECDH shared secret)
def ecc_decrypt_key(encrypted_key, private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
    return derived_key

# Performance measurement for encryption/decryption
def measure_performance(file_size):
    # Generate random file data of the specified size
    file_data = os.urandom(file_size)

    # Generate AES key
    aes_key = generate_aes_key()

    # AES file encryption
    start_time = time.time()
    iv, ciphertext = encrypt_file(file_data, aes_key)
    aes_encrypt_time = time.time() - start_time
    print(f"AES Encryption time: {aes_encrypt_time:.4f} seconds for {file_size / (1024 * 1024)} MB file")

    # RSA encryption of AES key
    start_time = time.time()
    rsa_encrypted_key = rsa_encrypt_key(aes_key, rsa_public_key)
    rsa_encrypt_time = time.time() - start_time
    print(f"RSA Key Encryption time: {rsa_encrypt_time:.4f} seconds")

    # RSA decryption of AES key
    start_time = time.time()
    rsa_decrypted_key = rsa_decrypt_key(rsa_encrypted_key, rsa_private_key)
    rsa_decrypt_time = time.time() - start_time
    print(f"RSA Key Decryption time: {rsa_decrypt_time:.4f} seconds")

    # ECC encryption of AES key
    start_time = time.time()
    ecc_encrypted_key = ecc_encrypt_key(aes_key, ecc_public_key)
    ecc_encrypt_time = time.time() - start_time
    print(f"ECC Key Encryption time: {ecc_encrypt_time:.4f} seconds")

    # ECC decryption of AES key
    start_time = time.time()
    ecc_decrypted_key = ecc_decrypt_key(ecc_encrypted_key, ecc_private_key, ecc_public_key)
    ecc_decrypt_time = time.time() - start_time
    print(f"ECC Key Decryption time: {ecc_decrypt_time:.4f} seconds")

    # AES file decryption
    start_time = time.time()
    decrypted_file = decrypt_file(iv, ciphertext, aes_key)
    aes_decrypt_time = time.time() - start_time
    print(f"AES Decryption time: {aes_decrypt_time:.4f} seconds for {file_size / (1024 * 1024)} MB file")

# RSA and ECC Key Generation
rsa_private_key, rsa_public_key, rsa_keygen_time = generate_rsa_keys()
print(f"RSA key generation time: {rsa_keygen_time:.4f} seconds")

ecc_private_key, ecc_public_key, ecc_keygen_time = generate_ecc_keys()
print(f"ECC key generation time: {ecc_keygen_time:.4f} seconds")

# Performance measurement for different file sizes
measure_performance(1 * 1024 * 1024)  # 1 MB file
measure_performance(10 * 1024 * 1024)  # 10 MB file
