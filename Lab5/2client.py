# Using socket programming in Python, demonstrate the application of
# hash functions for ensuring data integrity during transmission over a
# network. Write server and client scripts where the server computes the
# hash of received data and sends it back to the client, which then verifies
# the integrity of the data by comparing the received hash with the locally
# computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.
import socket
import hashlib


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

data = b"Hello, this is a test message."

client_socket.sendall(data)

received_hash  = client_socket.recv(2048)


received_hash = received_hash.decode()

computed_hash = hashlib.sha256(data).hexdigest()

if computed_hash == received_hash:
    print("Data integrity verified: Hashes match! 😊")
else:
    print("Data integrity check failed: Hashes do not match!")

client_socket.close()