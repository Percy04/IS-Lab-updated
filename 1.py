# Try using the Elgammal, Schnor asymmetric encryption standard and
# verify the above steps.
import random
import sympy
from sympy import mod_inverse


def genprime(bits=16):
    while True:
        p = random.getrandbits(bits)
        if sympy.isprime(p):
            return p

def L(u,n):
    return (u - 1) // n

def genkeypair():
    p = genprime()
    q = genprime()
    n = p * q
    lam = sympy.lcm(p - 1, q - 1)
    g = random.randint(1, n * n)

    lam = int(lam)
    mu = mod_inverse(L(pow(g, lam, n * n),n), n)

    return (n, g), (lam, mu)


def encrypt(pubk, msg):
    n, g = pubk
    while True:
        r = random.randint(1, n - 1)
        if sympy.gcd(r, n) == 1:
            break
    c = (pow(g, msg, n * n) * pow(r, n, n * n)) % (n * n)
    return c


def decrypt(prik, ct, pubk):
    n, _ = pubk
    lam, mu = prik
    msg = (L(pow(ct, lam, n * n),n) * mu) % n
    return msg


def homadd(c1, c2, pubk):
    n, _ = pubk
    return (c1 * c2) % (n * n)


if __name__ == "__main__":
    num1 = 17
    num2 = 20

    pubk, prik = genkeypair()

    c1 = encrypt(pubk, num1)
    c2 = encrypt(pubk, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    c = homadd(c1, c2, pubk)
    print(f"Encrypted sum: {c}")

    dec = decrypt(prik, c, pubk)
    print(f"Decrypted sum: {dec}")

    print(f"Original sum: {num1 + num2}")
