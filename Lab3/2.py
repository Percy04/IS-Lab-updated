# Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with
# the public key. Then decrypt the ciphertext with the private key to verify the original message.
import tinyec.ec as ec
from tinyec import registry
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Choose an elliptic curve (e.g., brainpoolP256r1)
curve = registry.get_curve("brainpoolP256r1")

# Generate recipient's private-public key pair
recipient_private_key = secrets.randbelow(curve.field.n)
recipient_public_key = recipient_private_key * curve.g

# Generate sender's private-public key pair
sender_private_key = secrets.randbelow(curve.field.n)
sender_public_key = sender_private_key * curve.g

# Key Exchange: Derive shared secret for encryption (from sender's perspective)
shared_secret = sender_public_key * recipient_private_key

# Convert the shared secret x-coordinate to a symmetric key (byte string)
symmetric_key = shared_secret.x.to_bytes((shared_secret.x.bit_length() + 7) // 8, 'big')[:16]  # AES key length is 16 bytes

# Encrypt the message "Secure Transactions" using AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

# Decrypt the message using AES
def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

# Convert bytes to Base64 string
def to_base64(data):
    return base64.b64encode(data).decode('utf-8')

# Convert Base64 string to bytes
def from_base64(data):
    return base64.b64decode(data)

# Encrypt the message
plaintext_message = b"Secure Transactions"
ciphertext = encrypt_message(plaintext_message, symmetric_key)

# Convert ciphertext to Base64 string
ciphertext_base64 = to_base64(ciphertext)
print(f"Ciphertext (Base64): {ciphertext_base64}")

# Convert Base64 string back to bytes
ciphertext_bytes = from_base64(ciphertext_base64)

# Key Exchange: Derive the same shared secret for decryption (from recipient's perspective)
decryption_shared_secret = sender_public_key * recipient_private_key
decryption_symmetric_key = decryption_shared_secret.x.to_bytes((decryption_shared_secret.x.bit_length() + 7) // 8, 'big')[:16]  # AES key length is 16 bytes

# Decrypt the message
decrypted_message = decrypt_message(ciphertext_bytes, decryption_symmetric_key)

print(f"Original message: {plaintext_message.decode('utf-8')}")
print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
