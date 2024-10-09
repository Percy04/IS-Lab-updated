import os
import json
import logging
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from rabin import Rabin  # Ensure you have the Rabin cryptosystem implementation
from cryptography.hazmat.primitives.asymmetric import dh

# Logger setup for auditing and compliance
logging.basicConfig(filename='hospital_management.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Class to manage RSA keys
class RSAKeyStore:
    def __init__(self, key_size=2048):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        self.public_key = self.private_key.public_key()
    
    def get_keys(self):
        private_pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL)
        public_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, 
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return private_pem, public_pem

# Class to manage Rabin keys
class RabinKeyStore:
    def __init__(self):
        self.rabin = Rabin(1024)  # 1024-bit key size for Rabin

    def get_keys(self):
        return self.rabin.public_key, self.rabin.private_key

# Patient record
class PatientRecord:
    def __init__(self, name, age, symptoms):
        self.name = name
        self.age = age
        self.symptoms = symptoms

    def __str__(self):
        return f"Patient Record - Name: {self.name}, Age: {self.age}, Symptoms: {self.symptoms}"

# Digital signing and verification
class DigitalSignature:
    def __init__(self, rsa_key_store):
        self.rsa_key_store = rsa_key_store

    def sign(self, data):
        signature = self.rsa_key_store.private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, signature, data, public_key):
        public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        try:
            public_key.verify(
                base64.b64decode(signature),
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logging.error(f"Verification failed: {e}")
            return False

# Main hospital management system
class HospitalManagementSystem:
    def __init__(self):
        self.rsa_key_store = RSAKeyStore()
        self.rabin_key_store = RabinKeyStore()
        self.digital_signature = DigitalSignature(self.rsa_key_store)

    def create_patient_record(self):
        name = input("Enter Patient Name: ")
        age = input("Enter Patient Age: ")
        symptoms = input("Enter Patient Symptoms: ")
        return PatientRecord(name, age, symptoms)

    def nurse_to_doctor(self, patient_record):
        data = str(patient_record).encode('utf-8')
        signature = self.digital_signature.sign(data)
        logging.info(f"Nurse sent patient record: {patient_record}")
        return data, signature

    def doctor_verification(self, data, signature):
        public_key = self.rsa_key_store.public_key
        is_verified = self.digital_signature.verify(signature, data, public_key)
        if is_verified:
            print("Doctor: Signature verified.")
            return True
        else:
            print("Doctor: Signature verification failed.")
            return False

    def radiologist_response(self, issue):
        public_key, private_key = self.rabin_key_store.get_keys()
        rabin = Rabin(1024)
        ciphertext = rabin.encrypt(issue)
        logging.info("Radiologist sent the issue back to the doctor.")
        return ciphertext

    def doctor_decrypt(self, ciphertext):
        _, private_key = self.rabin_key_store.get_keys()
        rabin = Rabin(1024)
        issue = rabin.decrypt(ciphertext, private_key)
        logging.info(f"Doctor received the issue: {issue}")
        return issue

    def revoke_keys(self):
        logging.info("Revoking all keys and cleaning up.")
        self.rsa_key_store = None
        self.rabin_key_store = None
        print("All keys have been revoked.")

    def exit_system(self):
        self.revoke_keys()
        print("Exiting the system.")

# Main execution flow
if __name__ == "__main__":
    system = HospitalManagementSystem()
    while True:
        print("\n--- Hospital Management System ---")
        print("1. Nurse writes a patient record")
        print("2. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            patient_record = system.create_patient_record()
            data, signature = system.nurse_to_doctor(patient_record)

            if system.doctor_verification(data, signature):
                issue = "X-ray shows fracture."  # Example issue
                ciphertext = system.radiologist_response(issue)
                decrypted_issue = system.doctor_decrypt(ciphertext)
                print(f"Decrypted issue from Radiologist: {decrypted_issue}")
        elif choice == '2':
            system.exit_system()
            break
        else:
            print("Invalid choice. Please select again.")
