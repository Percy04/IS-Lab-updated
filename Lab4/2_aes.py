import os
import json
import logging
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

# Logger setup for auditing and compliance
logging.basicConfig(filename='key_management_aes.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Utility function to derive a key from a password
def derive_key(password, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Secure storage for AES keys
class KeyStore:
    def __init__(self, store_file='keystore_aes.json'):
        self.store_file = store_file
        self.keys = self.load_keys()

    def load_keys(self):
        if os.path.exists(self.store_file):
            with open(self.store_file, 'r') as file:
                return json.load(file)
        return {}

    def save_keys(self):
        with open(self.store_file, 'w') as file:
            json.dump(self.keys, file)

    def store_symmetric_key(self, hospital_id, aes_key, salt):
        # Store AES key securely (salt and base64 encoded key)
        aes_key_encoded = urlsafe_b64encode(aes_key).decode('utf-8')
        self.keys[hospital_id] = {"aes_key": aes_key_encoded, "salt": urlsafe_b64encode(salt).decode('utf-8')}
        self.save_keys()

    def get_symmetric_key(self, hospital_id):
        key_data = self.keys.get(hospital_id)
        if key_data:
            aes_key = urlsafe_b64decode(key_data['aes_key'])
            salt = urlsafe_b64decode(key_data['salt'])
            return aes_key, salt
        return None

    def revoke_key(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()

# Centralized Key Management Service
class KeyManagementService:
    def __init__(self, keystore):
        self.keystore = keystore
        self.salt_size = 16  # Size of the salt for key derivation

    def generate_aes_key(self, password):
        # Generate a random salt for key derivation
        salt = urandom(self.salt_size)
        aes_key = derive_key(password, salt)
        return aes_key, salt

    def generate_and_store_key(self, hospital_id, password):
        aes_key, salt = self.generate_aes_key(password)
        self.keystore.store_symmetric_key(hospital_id, aes_key, salt)
        logging.info(f"Generated AES key for {hospital_id}")
        return aes_key, salt

    def get_key(self, hospital_id):
        key_data = self.keystore.get_symmetric_key(hospital_id)
        if key_data:
            aes_key, salt = key_data
            return aes_key, salt
        logging.warning(f"Key for {hospital_id} not found")
        return None

    def revoke_key(self, hospital_id):
        self.keystore.revoke_key(hospital_id)
        logging.info(f"Revoked keys for {hospital_id}")

    def renew_key(self, hospital_id, password):
        self.revoke_key(hospital_id)  # Revoke the old key
        return self.generate_and_store_key(hospital_id, password)  # Generate new key

    def audit_logs(self):
        with open('key_management_aes.log', 'r') as log_file:
            return log_file.readlines()

# API endpoints for key distribution and management
class KeyManagementAPI:
    def __init__(self, key_service):
        self.key_service = key_service

    def request_key(self, hospital_id, password):
        aes_key, salt = self.key_service.generate_and_store_key(hospital_id, password)
        return {"aes_key": urlsafe_b64encode(aes_key).decode('utf-8'), "salt": urlsafe_b64encode(salt).decode('utf-8')}

    def request_existing_key(self, hospital_id):
        key_data = self.key_service.get_key(hospital_id)
        if key_data:
            aes_key, salt = key_data
            return {"aes_key": urlsafe_b64encode(aes_key).decode('utf-8'), "salt": urlsafe_b64encode(salt).decode('utf-8')}
        return {"error": "Key not found"}

    def revoke_key(self, hospital_id):
        self.key_service.revoke_key(hospital_id)
        return {"message": f"Key for {hospital_id} has been revoked"}

    def renew_key(self, hospital_id, password):
        aes_key, salt = self.key_service.renew_key(hospital_id, password)
        return {"aes_key": urlsafe_b64encode(aes_key).decode('utf-8'), "salt": urlsafe_b64encode(salt).decode('utf-8')}

    def audit(self):
        return self.key_service.audit_logs()

# Example usage
if __name__ == "__main__":
    keystore = KeyStore()
    key_service = KeyManagementService(keystore)
    api = KeyManagementAPI(key_service)

    # Key Generation for Hospital A and B
    hospital_A_keys = api.request_key("Hospital_A", "password123")
    hospital_B_keys = api.request_key("Hospital_B", "passwordABC")

    print("Hospital A Key:", hospital_A_keys)
    print("Hospital B Key:", hospital_B_keys)

    # Request existing key for Hospital A
    hospital_A_existing_key = api.request_existing_key("Hospital_A")
    print("Hospital A Existing Key:", hospital_A_existing_key)

    # Revoke Hospital A's key
    revoke_response = api.revoke_key("Hospital_A")
    print(revoke_response)

    # Renew Hospital B's key
    renew_response = api.renew_key("Hospital_B", "newpasswordXYZ")
    print("Hospital B Key Renewal:", renew_response)

    # Auditing logs
    logs = api.audit()
    print("Audit Logs:")
    for log in logs:
        print(log.strip())
