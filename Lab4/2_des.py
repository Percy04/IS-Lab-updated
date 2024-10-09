import os
import json
import logging
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

# Logger setup for auditing and compliance
logging.basicConfig(filename='key_management_des.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Utility function to pad plaintext to be a multiple of DES block size (8 bytes)
def pad(data):
    padder = padding.PKCS7(algorithms.DES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Utility function to unpad decrypted data
def unpad(data):
    unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Secure storage for DES keys
class KeyStore:
    def __init__(self, store_file='keystore_des.json'):
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

    def store_symmetric_key(self, hospital_id, des_key):
        # Store DES key securely (base64 encoded key)
        des_key_encoded = urlsafe_b64encode(des_key).decode('utf-8')
        self.keys[hospital_id] = {"des_key": des_key_encoded}
        self.save_keys()

    def get_symmetric_key(self, hospital_id):
        key_data = self.keys.get(hospital_id)
        if key_data:
            des_key = urlsafe_b64decode(key_data['des_key'])
            return des_key
        return None

    def revoke_key(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()

# Centralized Key Management Service
class KeyManagementService:
    def __init__(self, keystore):
        self.keystore = keystore

    def generate_des_key(self):
        # Generate a random 56-bit DES key (7 bytes)
        des_key = urandom(8)[:7]  # DES uses 56 bits (7 bytes)
        return des_key

    def generate_and_store_key(self, hospital_id):
        des_key = self.generate_des_key()
        self.keystore.store_symmetric_key(hospital_id, des_key)
        logging.info(f"Generated DES key for {hospital_id}")
        return des_key

    def get_key(self, hospital_id):
        des_key = self.keystore.get_symmetric_key(hospital_id)
        if des_key:
            return des_key
        logging.warning(f"Key for {hospital_id} not found")
        return None

    def revoke_key(self, hospital_id):
        self.keystore.revoke_key(hospital_id)
        logging.info(f"Revoked keys for {hospital_id}")

    def renew_key(self, hospital_id):
        self.revoke_key(hospital_id)  # Revoke the old key
        return self.generate_and_store_key(hospital_id)  # Generate new key

    def audit_logs(self):
        with open('key_management_des.log', 'r') as log_file:
            return log_file.readlines()

# API endpoints for key distribution and management
class KeyManagementAPI:
    def __init__(self, key_service):
        self.key_service = key_service

    def request_key(self, hospital_id):
        des_key = self.key_service.generate_and_store_key(hospital_id)
        return {"des_key": urlsafe_b64encode(des_key).decode('utf-8')}

    def request_existing_key(self, hospital_id):
        des_key = self.key_service.get_key(hospital_id)
        if des_key:
            return {"des_key": urlsafe_b64encode(des_key).decode('utf-8')}
        return {"error": "Key not found"}

    def revoke_key(self, hospital_id):
        self.key_service.revoke_key(hospital_id)
        return {"message": f"Key for {hospital_id} has been revoked"}

    def renew_key(self, hospital_id):
        des_key = self.key_service.renew_key(hospital_id)
        return {"des_key": urlsafe_b64encode(des_key).decode('utf-8')}

    def audit(self):
        return self.key_service.audit_logs()

# Example usage
if __name__ == "__main__":
    keystore = KeyStore()
    key_service = KeyManagementService(keystore)
    api = KeyManagementAPI(key_service)

    # Key Generation for Hospital A and B
    hospital_A_keys = api.request_key("Hospital_A")
    hospital_B_keys = api.request_key("Hospital_B")

    print("Hospital A Key:", hospital_A_keys)
    print("Hospital B Key:", hospital_B_keys)

    # Request existing key for Hospital A
    hospital_A_existing_key = api.request_existing_key("Hospital_A")
    print("Hospital A Existing Key:", hospital_A_existing_key)

    # Revoke Hospital A's key
    revoke_response = api.revoke_key("Hospital_A")
    print(revoke_response)

    # Renew Hospital B's key
    renew_response = api.renew_key("Hospital_B")
    print("Hospital B Key Renewal:", renew_response)

    # Auditing logs
    logs = api.audit()
    print("Audit Logs:")
    for log in logs:
        print(log.strip())
