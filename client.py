import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import zfec
import os
import struct
import json
import base64

# Constants
M = 5  # Number of original chunks
R = 2  # Number of redundant chunks
CHUNK_SIZE = 1024  # Size of each file chunk in bytes
SERVER_NODES = ["http://127.0.0.1:5000", "http://127.0.0.1:5001", "http://127.0.0.1:5002"]
METADATA_SERVER_URL = "http://127.0.0.1:5003"

# 🔹 Global AES Key (Stored in Client)
GLOBAL_AES_KEY = get_random_bytes(32)  # AES-256 key
METADATA_ENCRYPTION_KEY = get_random_bytes(32)  # Key for metadata encryption

# AES encryption function
def encrypt_metadata(metadata, key):
    json_data = json.dumps(metadata).encode()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encrypted_data, tag = cipher.encrypt_and_digest(json_data)
    return base64.b64encode(nonce + tag + encrypted_data).decode()

# AES decryption function
def decrypt_metadata(encrypted_metadata, key):
    raw_data = base64.b64decode(encrypted_metadata)
    nonce, tag, encrypted_data = raw_data[:12], raw_data[12:28], raw_data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return json.loads(cipher.decrypt_and_verify(encrypted_data, tag).decode())

# Encrypt file using AES-256 in GCM mode
def encrypt_file(file_path):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    nonce = get_random_bytes(12)
    cipher = AES.new(GLOBAL_AES_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag

# Split file into chunks using erasure coding
def erasure_encode(data, m, r):
    original_length = len(data)
    padding_length = (m - ((len(data) + 4) % m)) % m
    data += b"\0" * padding_length
    data += struct.pack("I", original_length)
    block_size = len(data) // m
    blocks = [data[i * block_size: (i + 1) * block_size] for i in range(m)]
    encoder = zfec.Encoder(m, m + r)
    return encoder.encode(blocks)

def erasure_decode(chunks, m, r):
    decoder = zfec.Decoder(m, m + r)

    # Identify available chunks and their original indices
    available_indices = [i for i, chunk in enumerate(chunks) if chunk is not None]
    if len(available_indices) < m:
        raise ValueError(f"Need at least {m} chunks, but only {len(available_indices)} available.")

    # Select the first 'm' available indices (adjust if needed)
    selected_indices = available_indices[:m]

    # Extract chunks using the selected indices and convert to lists of integers
    selected_chunks = [list(chunks[i]) for i in selected_indices]

    # Debug info
    print("Selected Indices:", selected_indices)
    print("Selected Chunks (as lists of ints):", selected_chunks)

    # Decode the chunks
    blocks = decoder.decode(selected_indices, selected_chunks)

    # Reconstruct the original data
    data = b"".join(bytes(block) for block in blocks)
    original_length = struct.unpack("I", data[-4:])[0]
    return data[:original_length]







# Upload file to server nodes
def upload_file(file_path):
    # 🔹 Use the global AES key (No Shamir)
    key = GLOBAL_AES_KEY

    # Encrypt the file
    ciphertext, nonce, tag = encrypt_file(file_path)

    # Split the encrypted file into chunks
    chunks = erasure_encode(ciphertext, M, R)

    # Store chunks in server nodes
    chunk_locations = {}
    for i, chunk in enumerate(chunks):
        server_url = SERVER_NODES[i % len(SERVER_NODES)]
        chunk_id = f"{os.path.basename(file_path)}chunk{i}"
        response = requests.post(f"{server_url}/store_chunk", json={"chunk_id": chunk_id, "chunk_data": chunk.hex()})
        if response.status_code == 200:
            chunk_locations[chunk_id] = server_url

    # Encrypt metadata before storing
    metadata = {
        "file_name": os.path.basename(file_path),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "chunk_locations": chunk_locations,
    }
    
    encrypted_metadata = encrypt_metadata(metadata, METADATA_ENCRYPTION_KEY)
    print("Encrypted Meta data while uploading :",encrypted_metadata)

    # Store encrypted metadata on metadata server
    response = requests.post(f"{METADATA_SERVER_URL}/store_metadata", json={
        "file_name": os.path.basename(file_path),
        "encrypted_metadata": encrypted_metadata
    })

    if response.status_code == 200:
        print("File uploaded successfully.")
    else:
        print("Error storing metadata.")

# Download file from server nodes
def download_file(file_name):
    # Retrieve encrypted metadata from metadata server
    response = requests.get(f"{METADATA_SERVER_URL}/get_metadata/{file_name}")
    if response.status_code != 200:
        print("File not found.")
        return

    encrypted_metadata = response.json()["encrypted_metadata"]
    print("Encrypted meta data while downloading : ", encrypted_metadata)
    metadata = decrypt_metadata(encrypted_metadata, METADATA_ENCRYPTION_KEY)
    print(metadata)

    # Initialize empty chunk list
    chunks = [None] * (M + R)  # Ensure all chunks are placed in the right order

    # Retrieve chunks
    for chunk_id, server_url in metadata["chunk_locations"].items():
        response = requests.get(f"{server_url}/get_chunk/{chunk_id}")
        if response.status_code == 200:
            chunk_data = bytes.fromhex(response.json()["chunk_data"])
            index = int(chunk_id.split("chunk")[-1])  # Extract chunk index
            chunks[index] = chunk_data  # Store chunk at correct index
        else:
            print(f"Failed to retrieve chunk {chunk_id} from {server_url}.")

    # Filter out None values (missing chunks)
    available_chunks = [chunk for chunk in chunks if chunk is not None]
    print("Available chunks are : ",available_chunks)

    # **Reconstruct the encrypted file using erasure decoding**
    if len(available_chunks) >= M:
        ciphertext = erasure_decode(chunks, M, R)
    else:
        print("Not enough chunks to reconstruct the file.")
        return

    # 🔹 Use the global AES key (No Shamir)
    key = GLOBAL_AES_KEY

    # Decrypt the file
    nonce = bytes.fromhex(metadata["nonce"])
    tag = bytes.fromhex(metadata["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Save the decrypted file
    with open(f"downloaded_{file_name}", "wb") as f:
        f.write(plaintext)
    print(f"File downloaded and saved as downloaded_{file_name}.")


# Main function
def main():
    while True:
        print("\n1. Upload File")
        print("2. Download File")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            file_path = input("Enter the file path: ")
            upload_file(file_path)
        elif choice == "2":
            file_name = input("Enter the file name: ")
            download_file(file_name)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
