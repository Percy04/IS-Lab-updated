def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(ciphertext, a, b, m=26):
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        return "No modular inverse found for a =", a
    
    plaintext = []
    
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % m
            decrypted_char = chr(x + ord('A'))
            plaintext.append(decrypted_char)
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)

def find_affine_parameters(plaintext_pair, ciphertext_pair, m=26):
    (p1, p2) = plaintext_pair
    (c1, c2) = ciphertext_pair
    
    p1_num, p2_num = ord(p1) - ord('A'), ord(p2) - ord('A')
    c1_num, c2_num = ord(c1) - ord('A'), ord(c2) - ord('A')
    
    for a in range(1, m):
        if mod_inverse(a, m) is None:
            continue
        
        b = (c1_num - a * p1_num) % m
        if (a * p2_num + b) % m == c2_num:
            return a, b
    
    return None

# Known plaintext and ciphertext pairs
plaintext_pair = ("A", "B")
ciphertext_pair = ("G", "L")

# Find affine cipher parameters
parameters = find_affine_parameters(plaintext_pair, ciphertext_pair)

if parameters:
    a, b = parameters
    print(f"Affine cipher parameters found: a = {a}, b = {b}")

    # Ciphertext to decrypt
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    
    # Decrypt the ciphertext
    plaintext = affine_decrypt(ciphertext, a, b)
    print(f"Decrypted message: {plaintext}")
else:
    print("Affine cipher parameters not found.")
