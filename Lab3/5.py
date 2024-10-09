# As part of a project to enhance the security of communication in a peer-to-peer file sharing
# system, you are tasked with implementing a secure key exchange mechanism using the Diffie-
# Hellman algorithm. Each peer must establish a shared secret key with another peer over an
# insecure channel. Implement the Diffie-Hellman key exchange protocol, enabling peers to
# generate their public and private keys and securely compute the shared secret key. Measure
# the time taken for key generation and key exchange processes.
import time
import random
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_parameters():
    """Generate DH parameters."""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_keys(parameters):
    """Generate private and public keys."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_key(private_key, peer_public_key):
    """Compute the shared key."""
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

def main():
    # Generate DH parameters
    print("Generating DH parameters...")
    start_time = time.time()
    parameters = generate_parameters()
    end_time = time.time()
    print(f"DH parameters generated in {end_time - start_time:.6f} seconds.")

    # Peer A generates keys
    print("Peer A generating keys...")
    start_time = time.time()
    peer_a_private_key, peer_a_public_key = generate_keys(parameters)
    end_time = time.time()
    print(f"Peer A keys generated in {end_time - start_time:.6f} seconds.")

    # Peer B generates keys
    print("Peer B generating keys...")
    start_time = time.time()
    peer_b_private_key, peer_b_public_key = generate_keys(parameters)
    end_time = time.time()
    print(f"Peer B keys generated in {end_time - start_time:.6f} seconds.")

    # Exchange public keys and compute shared secret
    print("Computing shared secret key...")
    start_time = time.time()
    shared_secret_a = compute_shared_key(peer_a_private_key, peer_b_public_key)
    shared_secret_b = compute_shared_key(peer_b_private_key, peer_a_public_key)
    end_time = time.time()
    print(f"Shared secret computed in {end_time - start_time:.6f} seconds.")

    # Verify if both peers have the same shared secret
    print(f"Shared secret from Peer A: {shared_secret_a.hex()}")
    print(f"Shared secret from Peer B: {shared_secret_b.hex()}")
    if(shared_secret_a==shared_secret_b):
        print('Matched')
    

if __name__ == "__main__":
    main()
