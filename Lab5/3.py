# Design a Python-based experiment to analyze the performance of MD5,
# SHA-1, and SHA-256 hashing techniques in terms of computation time
# and collision resistance. Generate a dataset of random strings ranging
# from 50 to 100 strings, compute the hash values using each hashing
# technique, and measure the time taken for hash computation. Implement
# collision detection algorithms to identify any collisions within the
# hashed dataset.
import hashlib
import time
import random
import string

# Function to generate a random string
def generate_random_string(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Function to compute hash using a given algorithm
def compute_hash(algorithm: str, data: str) -> str:
    hash_func = hashlib.new(algorithm)
    hash_func.update(data.encode())
    return hash_func.hexdigest()

# Function to measure hash computation time and detect collisions
def analyze_hash_performance(num_strings: int, string_length: int):
    # Generate dataset
    dataset = [generate_random_string(string_length) for _ in range(num_strings)]
    
    # Initialize dictionaries to store hashes and times
    hashes = {'md5': {}, 'sha1': {}, 'sha256': {}}
    times = {'md5': 0, 'sha1': 0, 'sha256': 0}

    # Measure time and compute hashes
    for algorithm in hashes.keys():
        start_time = time.perf_counter()
        for s in dataset:
            hash_value = compute_hash(algorithm, s)
            hashes[algorithm][s] = hash_value
        times[algorithm] = time.perf_counter() - start_time

    # Collision detection
    def detect_collisions(hash_dict):
        seen = set()
        collisions = set()
        for original, hash_value in hash_dict.items():
            if hash_value in seen:
                collisions.add(hash_value)
            seen.add(hash_value)
        return collisions

    # Detect collisions for each algorithm
    collisions = {algo: detect_collisions(hashes[algo]) for algo in hashes.keys()}

    # Print results
    print(f"Number of strings: {num_strings}, String length: {string_length}")
    for algo in hashes.keys():
        print(f"\n{algo.upper()} Performance:")
        print(f"Time taken: {times[algo]:.4f} seconds")
        print(f"Number of collisions: {len(collisions[algo])}")
        if collisions[algo]:
            print(f"Colliding hashes: {collisions[algo]}")
        else:
            print("No collisions detected")

# Example usage
if __name__ == "__main__":
    # Define parameters
    num_strings = 100
    string_length = 50

    # Run the performance analysis
    analyze_hash_performance(num_strings, string_length)
