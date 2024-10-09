import os
import json
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_parameters, load_pem_private_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Logger setup for auditing and compliance
logging.basicConfig(filename='key_management_dh.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Secure storage for Diffie-Hellman keys
class KeyStore:
    def __init__(self, store_file='keystore_dh.json'):
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

    def store_key(self, hospital_id, private_key_pem, public_key_pem):
        self.keys[hospital_id] = {
            "private_key": private_key_pem.decode('utf-8'),
            "public_key": public_key_pem.decode('utf-8')
        }
        self.save_keys()

    def get_key_pair(self, hospital_id):
        key_data = self.keys.get(hospital_id)
        if key_data:
            return key_data['private_key'], key_data['public_key']
        return None

    def revoke_key(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()

# Centralized Key Management Service using Diffie-Hellman
class KeyManagementService:
    def __init__(self, keystore):
        self.keystore = keystore

    def generate_dh_parameters(self):
        # Generate DH parameters
        return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    def generate_key_pair(self, dh_parameters):
        # Generate private/public key pair
        private_key = dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        private_key_pem = private_key.private_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return private_key_pem, public_key_pem

    def generate_and_store_key(self, hospital_id, dh_parameters):
        private_key_pem, public_key_pem = self.generate_key_pair(dh_parameters)
        self.keystore.store_key(hospital_id, private_key_pem, public_key_pem)
        logging.info(f"Generated Diffie-Hellman key pair for {hospital_id}")
        return private_key_pem, public_key_pem

    def get_key_pair(self, hospital_id):
        key_data = self.keystore.get_key_pair(hospital_id)
        if key_data:
            return key_data
        logging.warning(f"Key pair for {hospital_id} not found")
        return None

    def revoke_key(self, hospital_id):
        self.keystore.revoke_key(hospital_id)
        logging.info(f"Revoked keys for {hospital_id}")

    def renew_key(self, hospital_id, dh_parameters):
        self.revoke_key(hospital_id)  # Revoke the old key
        return self.generate_and_store_key(hospital_id, dh_parameters)  # Generate new key

    def audit_logs(self):
        with open('key_management_dh.log', 'r') as log_file:
            return log_file.readlines()

# API endpoints for key distribution and management
class KeyManagementAPI:
    def __init__(self, key_service, dh_parameters):
        self.key_service = key_service
        self.dh_parameters = dh_parameters

    def request_key_pair(self, hospital_id):
        private_key_pem, public_key_pem = self.key_service.generate_and_store_key(hospital_id, self.dh_parameters)
        return {"private_key": private_key_pem.decode('utf-8'), "public_key": public_key_pem.decode('utf-8')}

    def request_existing_key_pair(self, hospital_id):
        key_data = self.key_service.get_key_pair(hospital_id)
        if key_data:
            private_key_pem, public_key_pem = key_data
            return {"private_key": private_key_pem, "public_key": public_key_pem}
        return {"error": "Key pair not found"}

    def revoke_key(self, hospital_id):
        self.key_service.revoke_key(hospital_id)
        return {"message": f"Key pair for {hospital_id} has been revoked"}

    def renew_key(self, hospital_id):
        private_key_pem, public_key_pem = self.key_service.renew_key(hospital_id, self.dh_parameters)
        return {"private_key": private_key_pem.decode('utf-8'), "public_key": public_key_pem.decode('utf-8')}

    def audit(self):
        return self.key_service.audit_logs()

# Example usage
if __name__ == "__main__":
    # Diffie-Hellman parameters (shared among participants)
    key_service = KeyManagementService(KeyStore())
    dh_parameters = key_service.generate_dh_parameters()
    api = KeyManagementAPI(key_service, dh_parameters)

    # Key Generation for Hospital A and B
    hospital_A_keys = api.request_key_pair("Hospital_A")
    hospital_B_keys = api.request_key_pair("Hospital_B")

    print("Hospital A Key Pair:", hospital_A_keys)
    print("Hospital B Key Pair:", hospital_B_keys)

    # Request existing key pair for Hospital A
    hospital_A_existing_key = api.request_existing_key_pair("Hospital_A")
    print("Hospital A Existing Key Pair:", hospital_A_existing_key)

    # Revoke Hospital A's key pair
    revoke_response = api.revoke_key("Hospital_A")
    print(revoke_response)

    # Renew Hospital B's key pair
    renew_response = api.renew_key("Hospital_B")
    print("Hospital B Key Pair Renewal:", renew_response)

    # Auditing logs
    logs = api.audit()
    print("Audit Logs:")
    for log in logs:
        print(log.strip())
