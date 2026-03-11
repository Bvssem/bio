# crypto_engine.py
import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hash_data(data_string: str) -> str:
    """Hashes data using SHA-256."""
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

def encrypt_fragment(key: bytes, fragment_dict: dict) -> bytes:
    """Encrypts a dictionary using AES-256 GCM."""
    aesgcm = AESGCM(key)
    # GCM requires a unique 12-byte nonce per encryption
    nonce = os.urandom(12) 
    data_bytes = json.dumps(fragment_dict).encode('utf-8')
    
    ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data=None)
    
    # Prepend the nonce to the ciphertext so we can use it during decryption
    return nonce + ciphertext

def decrypt_fragment(key: bytes, encrypted_data: bytes) -> dict:
    """Decrypts AES-256 GCM data back into a dictionary."""
    aesgcm = AESGCM(key)
    
    # Extract the 12-byte nonce and the actual ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(decrypted_bytes.decode('utf-8'))