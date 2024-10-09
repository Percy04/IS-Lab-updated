# Using socket programming in Python, demonstrate the application of
# hash functions for ensuring data integrity during transmission over a
# network. Write server and client scripts where the server computes the
# hash of received data and sends it back to the client, which then verifies
# the integrity of the data by comparing the received hash with the locally
# computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.
import socket
import hashlib

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is on")
conn,addr=server_socket.accept()
print('Server Connected')

data = conn.recv(1024)


data_hash = hashlib.sha256(data).hexdigest()

conn.send(data_hash.encode())

conn.close()
