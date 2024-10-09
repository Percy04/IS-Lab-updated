import socket
from Crypto.Util import number
from Crypto.Hash import SHA256
import random
import json

def generate_large_prime(bits):
    return number.getPrime(bits)

def generate_key_pair(p, g):
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def sign_message(message, p, g, x):
    h = SHA256.new(message.encode())
    hash_message = int.from_bytes(h.digest(), byteorder='big')

    while True:
        k = random.randint(1, p - 2)
        if number.GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = number.inverse(k, p - 1)
    s = (k_inv * (hash_message - x * r)) % (p - 1)
    return (r, s)

def main():
    bits = 512
    p = generate_large_prime(bits)
    g = random.randint(2, p - 1)
    public_key, private_key = generate_key_pair(p, g)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Send p, g, and public key to the client
    conn.sendall(json.dumps({"p": p, "g": g, "y": public_key[2]}).encode())

    # Receive message from client
    message = conn.recv(1024).decode()
    print(f"Received message: {message}")

    # Sign the message
    signature = sign_message(message, p, g, private_key)
    signature_str = str(signature)  # Convert tuple to string
    conn.sendall(signature_str.encode())
    print(f"Signature sent: {signature}")

    conn.close()

if __name__ == "__main__":
    main()
