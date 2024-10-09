# Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with
# the public key. Then decrypt the ciphertext with the private key to verify the original message.
from tinyec import registry
import secrets

# ECC curve: Using a well-known curve from the tinyec registry
curve = registry.get_curve('brainpoolP256r1')

# Generate a private key and the corresponding public key
private_key = secrets.randbelow(curve.field.n)
public_key = private_key * curve.g  # g is the generator point on the curve

# Function to encrypt the message
def encrypt_ECC(msg, pubKey):
    # Generate an ephemeral key pair
    ephemeral_key = secrets.randbelow(curve.field.n)
    shared_point = ephemeral_key * pubKey
    ciphertext = (shared_point.x, shared_point.y, ephemeral_key * curve.g)
    
    # Convert message to bytes and encrypt by XORing with shared point's x-coordinate
    encrypted_msg = [ord(c) ^ shared_point.x for c in msg]
    
    return ciphertext, encrypted_msg

# Function to decrypt the message
def decrypt_ECC(ciphertext, encrypted_msg, privKey):
    shared_point = privKey * ciphertext[2]
    
    # Decrypt by XORing the ciphertext with the shared point's x-coordinate
    decrypted_msg = ''.join([chr(c ^ shared_point.x) for c in encrypted_msg])
    
    return decrypted_msg

# Message to be encrypted
message = "Secure Transactions"

# Encrypt the message using the public key
ciphertext, encrypted_message = encrypt_ECC(message, public_key)
print("Encrypted message:", encrypted_message)

# Decrypt the message using the private key
decrypted_message = decrypt_ECC(ciphertext, encrypted_message, private_key)
print("Decrypted message:", decrypted_message)
