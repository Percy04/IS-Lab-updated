# hospital_management.py
import os
import random
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from rabin import Rabin

class HospitalManagementSystem:
    def __init__(self):
        self.nurse_private_key = self.generate_key_pair()
        self.nurse_public_key = self.nurse_private_key.public_key()
        self.doctor_public_key = self.generate_key_pair().public_key()  # For demonstration, create a new key
        self.rabin = Rabin(1024)  # Initialize Rabin for further communication

    def generate_key_pair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def create_patient_record(self):
        name = input("Enter patient's name: ")
        age = input("Enter patient's age: ")
        symptoms = input("Enter patient's symptoms: ")
        return {"name": name, "age": age, "symptoms": symptoms}

    def nurse_to_doctor(self, patient_record):
        record_json = json.dumps(patient_record)
        signature = self.nurse_private_key.sign(
            record_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return record_json, signature

    def doctor_verification(self, data, signature):
        try:
            self.doctor_public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified successfully.")
            return True
        except Exception as e:
            print("Signature verification failed.", e)
            return False

    def exit_system(self):
        print("Exiting the system.")
        exit()

# Rabin Class Definition (from the previous message)
# Put this in a separate rabin.py file
import random
from sympy import isprime, nextprime

class Rabin:
    def __init__(self, key_size):
        self.p = self.generate_prime(key_size // 2)
        self.q = self.generate_prime(key_size // 2)
        self.n = self.p * self.q

    def generate_prime(self, bits):
        while True:
            prime_candidate = nextprime(random.getrandbits(bits))
            if isprime(prime_candidate):
                return prime_candidate

    def encrypt(self, plaintext):
        plaintext = int.from_bytes(plaintext.encode(), 'big')
        ciphertext = (plaintext ** 2) % self.n
        return ciphertext

    def decrypt(self, ciphertext):
        p = self.p
        q = self.q

        s1 = pow(ciphertext, (p + 1) // 4, p)
        s2 = (p - s1) % p
        t1 = pow(ciphertext, (q + 1) // 4, q)
        t2 = (q - t1) % q

        m1 = self.crt(s1, t1, p, q)
        m2 = self.crt(s1, t2, p, q)
        m3 = self.crt(s2, t1, p, q)
        m4 = self.crt(s2, t2, p, q)

        return [m1 % self.n, m2 % self.n, m3 % self.n, m4 % self.n]

    def crt(self, a, b, p, q):
        return (a * q * pow(q, -1, p) + b * p * pow(p, -1, q)) % (p * q)

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
                ciphertext = system.rabin.encrypt(issue)
                decrypted_issue = system.rabin.decrypt(ciphertext)
                print(f"Decrypted issue from Radiologist: {[bytes.fromhex(hex(val)[2:]).decode('utf-8', 'ignore') for val in decrypted_issue]}")
        elif choice == '2':
            system.exit_system()
            break
        else:
            print("Invalid choice. Please select again.")
