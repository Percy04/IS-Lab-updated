import numpy as np

# Function to convert a letter to its numerical value
def letter_to_num(letter):
    return ord(letter.lower()) - ord('a')

# Function to convert a number to its corresponding letter
def num_to_letter(num):
    return chr(num + ord('a'))

# Function to split the plaintext into pairs (blocks of 2)
def split_plaintext(plaintext):
    plaintext = plaintext.replace(" ", "").lower()  # Remove spaces and convert to lowercase
    if len(plaintext) % 2 != 0:
        plaintext += 'x'  # Pad with 'x' if the length is odd
    return [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]

# Function to encrypt using the Hill cipher
def hill_cipher_encrypt(plaintext, key_matrix):
    plaintext_pairs = split_plaintext(plaintext)
    ciphertext = ""
    
    for pair in plaintext_pairs:
        vector = np.array([[letter_to_num(pair[0])], [letter_to_num(pair[1])]])
        encrypted_vector = np.dot(key_matrix, vector) % 26  # Perform matrix multiplication and mod 26
        ciphertext += num_to_letter(encrypted_vector[0, 0]) + num_to_letter(encrypted_vector[1, 0])
    
    return ciphertext

# Main code
key_matrix = np.array([[3, 3], [2, 7]])  # The key matrix

plaintext = "We live in an insecure world"
ciphertext = hill_cipher_encrypt(plaintext, key_matrix)

print("Original Message:", plaintext)
print("Encrypted Message:", ciphertext)
