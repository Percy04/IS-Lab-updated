# Given an ElGamal encryption scheme with a public key (p, g, h) and a private key x, encrypt
# the message "Confidential Data". Then decrypt the ciphertext to retrieve the original message.
import random

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)

def gen_key(q):
    key = random.randint(10**20, q)
    while gcd(q, key) != 1:
        key = random.randint(10**20, q)
    return key

def power(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
        y = (y * y) % c
        b = int(b / 2)
    return x % c

def encrypt(msg, q, h, g):
    en_msg = []
    k = gen_key(q)  # Private key for sender
    s = power(h, k, q)
    p = power(g, k, q)
    for i in range(len(msg)):
        en_msg.append(msg[i])
    print("g^k used:", p)
    print("g^ak used:", s)
    for i in range(len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])
    return en_msg, p

def decrypt(en_msg, p, key, q):
    dr_msg = []
    h = power(p, key, q)
    for i in range(len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))
    return "".join(dr_msg)

def main():
    msg = "Confidential Data"
    print("Original Message:", msg)
    q = random.randint(10**20, 10**50)
    g = random.randint(2, q)
    key = gen_key(q)  # Private key for receiver
    h = power(g, key, q)
    print("g used:", g)
    print("g^a used:", h)
    en_msg, p = encrypt(msg, q, h, g)
    dr_msg = decrypt(en_msg, p, key, q)
    print("Decrypted Message:", dr_msg)

if __name__ == "__main__":
    main()
