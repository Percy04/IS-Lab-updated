import os
import json
import logging
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Logger setup for auditing and compliance
logging.basicConfig(filename='key_management_ecc.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Secure storage for private keys
class KeyStore:
    def __init__(self, store_file='keystore_ecc.json'):
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

    def store_private_key(self, hospital_id, private_key):
        # Serialize private key to PEM format and store securely
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        self.keys[hospital_id] = {"private_key": pem}
        self.save_keys()

    def get_private_key(self, hospital_id):
        key_data = self.keys.get(hospital_id)
        if key_data:
            return serialization.load_pem_private_key(
                key_data['private_key'].encode('utf-8'),
                password=None,
                backend=default_backend()
            )
        return None

    def revoke_key(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()

# Centralized Key Management Service
class KeyManagementService:
    def __init__(self, keystore):
        self.keystore = keystore
        self.public_keys = {}

    def generate_keys(self, hospital_id):
        # Generate ECC private key and derive the public key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Serialize public key to PEM format
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Store the private key in keystore and log the operation
        self.keystore.store_private_key(hospital_id, private_key)
        self.public_keys[hospital_id] = pem_public_key
        logging.info(f"Generated ECC keys for {hospital_id}")
        return {"public_key": pem_public_key, "private_key": private_key}

    def get_public_key(self, hospital_id):
        if hospital_id in self.public_keys:
            return self.public_keys[hospital_id]
        logging.warning(f"Public key for {hospital_id} not found")
        return None

    def revoke_key(self, hospital_id):
        self.keystore.revoke_key(hospital_id)
        if hospital_id in self.public_keys:
            del self.public_keys[hospital_id]
            logging.info(f"Revoked keys for {hospital_id}")
        else:
            logging.warning(f"No public key found for {hospital_id}")

    def renew_keys(self, hospital_id):
        self.revoke_key(hospital_id)  # Revoke the old key
        return self.generate_keys(hospital_id)  # Generate new keys

    def audit_logs(self):
        with open('key_management_ecc.log', 'r') as log_file:
            return log_file.readlines()

# API endpoints for key distribution and management
class KeyManagementAPI:
    def __init__(self, key_service):
        self.key_service = key_service

    def request_key_pair(self, hospital_id):
        keys = self.key_service.generate_keys(hospital_id)
        return {"public_key": keys['public_key'], "private_key": keys['private_key']}

    def request_public_key(self, hospital_id):
        public_key = self.key_service.get_public_key(hospital_id)
        if public_key:
            return {"public_key": public_key}
        return {"error": "Public key not found"}

    def revoke_key(self, hospital_id):
        self.key_service.revoke_key(hospital_id)
        return {"message": f"Keys for {hospital_id} have been revoked"}

    def renew_key(self, hospital_id):
        keys = self.key_service.renew_keys(hospital_id)
        return {"public_key": keys['public_key'], "private_key": keys['private_key']}

    def audit(self):
        return self.key_service.audit_logs()

# Example usage
if __name__ == "__main__":
    keystore = KeyStore()
    key_service = KeyManagementService(keystore)
    api = KeyManagementAPI(key_service)

    # Key Generation for Hospital A and B
    hospital_A_keys = api.request_key_pair("Hospital_A")
    hospital_B_keys = api.request_key_pair("Hospital_B")

    print("Hospital A Key Pair:", hospital_A_keys)
    print("Hospital B Key Pair:", hospital_B_keys)

    # Request public key for Hospital A
    hospital_A_pub_key = api.request_public_key("Hospital_A")
    print("Hospital A Public Key:", hospital_A_pub_key)

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
