# HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
# management system using the Rabin cryptosystem. The system allows authorized healthcare professionals to securely access and manage patient records across multiple hospitals and clinics within the organization. Implement a Python-based centralized key management service that can:
# Key Generation: Generate public and private key pairs for each hospital and clinic using
# the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
# • Key Distribution: Provide a secure API for hospitals and clinics to request and receive
# their public and private key pairs.
# • Key Revocation: Implement a process to revoke and update the keys of a hospital or
# clinic when necessary (e.g., when a facility is closed or compromised).
# • Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
# intervals (e.g., every 12 months) to maintain the security of the patient data management
# system.
# • Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring that
# they are not accessible to unauthorized parties.
# • Auditing and Logging: Maintain detailed logs of all key management operations, such
# as key generation, distribution, revocation, and renewal, to enable auditing and
# compliance reporting.
# • Regulatory Compliance: Ensure that the key management service and its operations are
# compliant with relevant data privacy regulations (e.g., HIPAA).
# • Perform a trade-off analysis to compare the workings of Rabin and RSA.
import os
import logging
import json
import time
import hashlib
import random
from sympy import nextprime, mod_inverse

# Logger setup for auditing and compliance
logging.basicConfig(filename='key_management.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Utility function to generate large prime numbers
def generate_large_prime(bits=512):
    return nextprime(random.getrandbits(bits))

# Rabin Cryptosystem Key Generation
def generate_rabin_keys(key_size=1024):
    p = generate_large_prime(key_size // 2)
    q = generate_large_prime(key_size // 2)
    n = p * q  # Public key (n)
    return {"p": p, "q": q, "n": n}

# Secure storage for private keys
class KeyStore:
    def __init__(self, store_file='keystore.json'):
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

    def store_private_key(self, hospital_id, p, q):
        # Store p and q securely for each hospital/clinic
        self.keys[hospital_id] = {"p": str(p), "q": str(q)}
        self.save_keys()

    def get_private_key(self, hospital_id):
        return self.keys.get(hospital_id)

    def revoke_key(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()

# Centralized Key Management Service
class KeyManagementService:
    def __init__(self, keystore):
        self.keystore = keystore
        self.public_keys = {}

    def generate_keys(self, hospital_id, key_size=1024):
        keys = generate_rabin_keys(key_size)
        self.keystore.store_private_key(hospital_id, keys['p'], keys['q'])
        self.public_keys[hospital_id] = keys['n']
        logging.info(f"Generated keys for {hospital_id}")
        return {"public_key": keys['n'], "private_key": {"p": keys['p'], "q": keys['q']}}

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

    def renew_keys(self, hospital_id, key_size=1024):
        self.revoke_key(hospital_id)  # Revoke the old key
        return self.generate_keys(hospital_id, key_size)  # Generate new keys

    def audit_logs(self):
        with open('key_management.log', 'r') as log_file:
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