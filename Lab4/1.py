# SecureCorp is a large enterprise with multiple subsidiaries and business units located across
# different geographical regions. As part of their digital transformation initiative, the IT team at
# SecureCorp has been tasked with building a secure and scalable communication system to
# enable seamless collaboration and information sharing between their various subsystems.
# The enterprise system consists of the following key subsystems:
# 1. Finance System (System A): Responsible for all financial record-keeping, accounting, and
# reporting.
# 2. HR System (System B): Manages employee data, payroll, and personnel-related processes.
# 3. Supply Chain Management (System C): Coordinates the flow of goods, services, and
# information across the organization's supply chain.
# These subsystems need to communicate securely and exchange critical documents, such as
# financial reports, employee contracts, and procurement orders, to ensure the enterprise's
# overall efficiency.
# The IT team at SecureCorp has identified the following requirements for the secure
# communication and document signing solution:
# 1. Secure Communication: The subsystems must be able to establish secure communication
# channels using a combination of RSA encryption and Diffie-Hellman key exchange.
# 2. Key Management: SecureCorp requires a robust key management system to generate,
# distribute, and revoke keys as needed to maintain the security of the enterprise system.
# 3. Scalability: The solution must be designed to accommodate the addition of new subsystems
# in the future as SecureCorp continues to grow and expand its operations.
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
import base64
import os

def generate_parameters():
    """Generate DH parameters."""
    return dh.generate_parameters(generator=2, key_size=2048)

class SecureCorpSystem:
    def __init__(self, name, para):
        self.name = name
        self.dh_parameters = para
        self.private_key = self.dh_parameters.generate_private_key()
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.shared_key = None
        self.pubkey=self.private_key.public_key()

    

    def generate_shared_key(self, peer_public_key):
        self.shared_key = self.private_key.exchange(peer_public_key)
        print(f"{self.name} shared key: {self.shared_key.hex()}")  # Debug output

    # def send_rsa_public_key(self):
    #     # Encrypt the RSA public key using the shared key (symmetric encryption)
    #     key = self.shared_key[:32]  # Use the first 32 bytes for AES
    #     key=bytes.fromhex(key)
    #     data=self.rsa_public_key
    #     ctext=cipher.encrypt(pad(data,AES.block_size))
    #     # Return nonce + tag + ciphertext
    #     return base64.b64encode(aes_cipher.nonce + tag + encrypted_key).decode()

    # def receive_rsa_public_key(self, encrypted_key):
    #     # Decrypt the received RSA public key
    #     encrypted_key = base64.b64decode(encrypted_key.encode())
    #     nonce, tag, ciphertext = encrypted_key[:12], encrypted_key[12:28], encrypted_key[28:]
    #     key = self.shared_key[:32]  # Use the first 32 bytes for AES
    #     aes_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    #     try:
    #         decrypted_key = aes_cipher.decrypt_and_verify(ciphertext, tag)
    #         return serialization.load_pem_public_key(decrypted_key)
    #     except Exception as e:
    #         print(f"Failed to decrypt RSA public key: {e}")
    #         return None

    def encrypt_message(self, message, recipient_rsa_public_key):
        # Encrypt the message using the recipient's RSA public key
        return base64.b64encode(recipient_rsa_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )).decode()

    def decrypt_message(self, encrypted_message):
        # Decrypt the message using the RSA private key
        encrypted_message = base64.b64decode(encrypted_message.encode())
        try:
            decrypted_message = self.rsa_private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_message.decode()
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def sign_document(self, document):
        signature = self.rsa_private_key.sign(
            document.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, document, signature,pubkey):
        signature = base64.b64decode(signature.encode())
        try:
            pubkey.verify(
                signature,
                document.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# Example usage
if __name__ == "__main__":
    para = generate_parameters()
    finance_system = SecureCorpSystem("Finance System", para)
    hr_system = SecureCorpSystem("HR System", para)

    # finance_public_key = finance_system.get_dh_public_key()
    # hr_public_key = hr_system.get_dh_public_key()

    finance_system.generate_shared_key(hr_system.pubkey)
    hr_system.generate_shared_key(finance_system.pubkey)
    print("matched") if finance_system.shared_key == hr_system.shared_key else None
    # Exchange RSA public keys securely
    hr_rsa_public_key = hr_system.rsa_public_key
    print(f"HR-FIN RSA Public Key: {hr_rsa_public_key}")

    if hr_rsa_public_key:
        print(f"HR RSA Public Key received successfully.")

        # Example message exchange using the received RSA public key
        message = "Confidential Financial Report"
        encrypted_message = finance_system.encrypt_message(message, hr_rsa_public_key)
        print(f"Encrypted message from Finance: {encrypted_message}")

        # HR decrypts the message using its private RSA key
        decrypted_message = hr_system.decrypt_message(encrypted_message)
        print(f"Decrypted message in HR: {decrypted_message}")

        # Document signing
        document = "Employee Contract"
        signature = hr_system.sign_document(document)
        print(f"Signature: {signature}")

        # Verify signature
        is_valid = finance_system.verify_signature(document, signature,hr_rsa_public_key)
        print(f"Signature valid: {is_valid}")
