import socket
from Crypto.Hash import SHA256
from Crypto.Util import number
import json
import random

def verify_signature(message, signature, p, g, y):
    r, s = signature
    h = SHA256.new(message.encode())
    hash_message = int.from_bytes(h.digest(), byteorder='big')

    v1 = pow(g, hash_message, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2

def compute_y(p, g, private_key):
    return pow(g, private_key, p)

def main():
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Receive p, g, and y from the server
    params = json.loads(client_socket.recv(1024).decode())
    p = params["p"]
    g = params["g"]
    y = params["y"]

    # Send a message
    message = "This is a test message."
    client_socket.sendall(message.encode())

    # Receive the signature
    signature_str = client_socket.recv(1024).decode()
    print(f"Received signature: {signature_str}")

    # Convert signature string back to tuple
    signature = eval(signature_str)  # Using eval here for simplicity; be cautious with eval in production

    # Verify the signature
    is_valid = verify_signature(message, signature, p, g, y)
    print(f"Signature valid: {is_valid}")

    client_socket.close()

if __name__ == "__main__":
    main()
