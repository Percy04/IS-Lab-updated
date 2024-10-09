# Compare the encryption and decryption times for DES and AES-256 for the message
# "Performance Testing of Encryption Algorithms". Use a standard implementation and report
# your findings.
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

# Constants
message = "Performance Testing of Encryption Algorithms"
key_des = get_random_bytes(8)  # DES key length is 8 bytes
key_aes = get_random_bytes(32) # AES-256 key length is 32 bytes
iv_des = get_random_bytes(8)   # DES requires an 8-byte IV
iv_aes = get_random_bytes(16)  # AES requires a 16-byte IV

# Convert message to bytes
data = message.encode()

# DES Encryption and Decryption
def test_des():
    cipher_des = DES.new(key_des, DES.MODE_CBC, iv=iv_des)
    start_time = time.time()
    ciphertext_des = cipher_des.encrypt(pad(data, DES.block_size))
    end_time = time.time()
    encryption_time_des = end_time - start_time

    cipher_des_decrypt = DES.new(key_des, DES.MODE_CBC, iv=iv_des)
    start_time = time.time()
    plaintext_des = unpad(cipher_des_decrypt.decrypt(ciphertext_des), DES.block_size)
    end_time = time.time()
    decryption_time_des = end_time - start_time

    return encryption_time_des, decryption_time_des

# AES-256 Encryption and Decryption
def test_aes():
    cipher_aes = AES.new(key_aes, AES.MODE_CBC, iv=iv_aes)
    start_time = time.time()
    ciphertext_aes = cipher_aes.encrypt(pad(data, AES.block_size))
    end_time = time.time()
    encryption_time_aes = end_time - start_time

    cipher_aes_decrypt = AES.new(key_aes, AES.MODE_CBC, iv=iv_aes)
    start_time = time.time()
    plaintext_aes = unpad(cipher_aes_decrypt.decrypt(ciphertext_aes), AES.block_size)
    end_time = time.time()
    decryption_time_aes = end_time - start_time

    return encryption_time_aes, decryption_time_aes

# Perform tests
encryption_time_des, decryption_time_des = test_des()
encryption_time_aes, decryption_time_aes = test_aes()

# Print results
print(f"DES Encryption Time: {encryption_time_des:.10f} seconds")
print(f"DES Decryption Time: {decryption_time_des:.10f} seconds")
print(f"AES-256 Encryption Time: {encryption_time_aes:.6f} seconds")
print(f"AES-256 Decryption Time: {decryption_time_aes:.6f} seconds")
