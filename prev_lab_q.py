from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
import random


# 1. Key Generation for ElGamal
def generate_keys():
    p = getPrime(256)  # Large prime number
    g = 2  # Using a common generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return (p, g, h, x)


# 2. Signing Function
def elgamal_sign(message, p, g, x):
    while True:
        k = random.randint(1, p - 2)  # Random ephemeral key
        if GCD(k, p - 1) == 1:  # Check if `k` is coprime with `p-1`
            break

    r = pow(g, k, p)  # Compute r = g^k mod p
    m = bytes_to_long(message)  # Convert message to a long integer
    k_inv = inverse(k, p - 1)  # Calculate the inverse of k
    s = (k_inv * (m - x * r)) % (p - 1)  # Compute s
    return (r, s)


# 3. Verification Function
def elgamal_verify(message, r, s, p, g, h):
    if not (0 < r < p) or not (0 < s < p - 1):  # Check ranges
        return False
    m = bytes_to_long(message)
    v1 = pow(g, m, p)  # v1 = g^m mod p
    v2 = (pow(h, r, p) * pow(r, s, p)) % p  # v2 = (h^r * r^s) mod p
    return v1 == v2
# Function to generate Rabin keys (p, q, n) using pycryptodome
def rabin_keygen(bit_size=512):
    """Generate Rabin keys where both primes are congruent to 3 mod 4."""
    # Generate two large primes p and q such that p ≡ 3 (mod 4) and q ≡ 3 (mod 4)
    while True:
        p = getPrime(bit_size // 2)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bit_size // 2)
        if q % 4 == 3:
            break
    n = p * q
    return (p, q, n)


# Rabin encryption: c = (m^2) % n
def rabin_encrypt(n, message):
    """Encrypt a message using Rabin encryption."""
    m = int.from_bytes(message.encode('utf-8'), 'big')  # Convert message to integer
    return (m * m) % n


# Rabin decryption using the Chinese Remainder Theorem (CRT)
def rabin_decrypt(p, q, n, ciphertext):
    """Decrypt a Rabin-encrypted message."""
    # Calculate the roots modulo p and q
    mp = pow(ciphertext, (p + 1) // 4, p)  # Decrypt using p
    mq = pow(ciphertext, (q + 1) // 4, q)  # Decrypt using q

    # Use the CRT to find the four possible roots
    q_inv = inverse(q, p)
    p_inv = inverse(p, q)

    # Four potential roots
    r1 = (mp * q * q_inv + mq * p * p_inv) % n
    r2 = (mp * q * q_inv - mq * p * p_inv) % n
    r3 = n - r1
    r4 = n - r2

    possible_roots = [r1, r2, r3, r4]
    valid_decryptions = []

    # Convert each root to bytes and try to decode as UTF-8
    for i, root in enumerate(possible_roots):
        try:
            decrypted_message = root.to_bytes((root.bit_length() + 7) // 8, 'big').decode('utf-8')
            print(f"Possible message option {i + 1}: {decrypted_message}")
            valid_decryptions.append(decrypted_message)
        except UnicodeDecodeError:
            print(f"Possible message option {i + 1}: [Invalid UTF-8 String]")

    # Return all possible valid messages
    if valid_decryptions:
        return valid_decryptions
    else:
        return ["Decryption failed: None of the roots are valid."]


# Main function with if-elif-else structure
def main():
    # Generate keys for demonstration
    p, g, h, x = generate_keys()
    print("Public Key (p, g, h):", (p, g, h))
    print("Private Key (x):", x)

    while True:
        print("\n--- ElGamal Digital Signature ---")
        print("1. Sign a Message by nurse")
        print("2. Verify a Message by doctor")
        print("3.Radiologist sends disease to doctor using Rabin:")
        print("4.Doctor recieves and decryts the diease")
        print("5.Revoke all keys")
        print("6. Exit")

        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        # Using if-elif-else instead of match-case
        if choice == 1:  # Signing Operation
            message = input("Enter the message to be signed: ").encode()
            r, s = elgamal_sign(message, p, g, x)
            print(f"\nMessage: {message.decode()}")
            print(f"Signature: (r: {r}, s: {s})")

        elif choice == 2:  # Verification Operation
            message = input("Enter the message to be verified: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verification_result = elgamal_verify(message, r, s, p, g, h)
                if verification_result:
                    print("\nSignature verified successfully! The message is authentic.")
                else:
                    print("\nSignature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")

        elif choice==3:
            # Key generation
            p, q, n = rabin_keygen()
            print(f"Public key (n): {n}")
            print(f"Private key (p, q): ({p}, {q})")

            # Message to encrypt
            message = input("Enter msg\n")
            print(f"\nOriginal message: {message}")

            # Encrypt the message
            ciphertext = rabin_encrypt(n, message)
            print(f"Encrypted message (ciphertext): {ciphertext}")
        elif choice==4:
            # Decrypt the ciphertext
            print("\nAttempting to decrypt the ciphertext...")
            decrypted_messages = rabin_decrypt(p, q, n, ciphertext)

            # Display all possible decrypted messages
            print("\nAll Possible Decrypted Messages:")
            for idx, msg in enumerate(decrypted_messages, 1):
                print(f"Option {idx}: {msg}")

        elif choice==5:
            
            p, g, h, x = None, None, None, None  # Revoke ElGamal keys
            rabin_p, rabin_q, rabin_n = None, None, None  # Revoke Rabin keys
            print("All keys have been revoked.")





        elif choice == 6:  # Exit
            print("Exiting the program.")
            break

        else:  # Default case, if no valid option is chosen
            print("Invalid choice! Please select a valid option.")


# Run the program
if __name__ == "__main__":
    main()