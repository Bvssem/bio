# test_phases_1_and_2.py
from config import CLIENT_KEY, SERVER_KEY
from biometrics import generate_biometric_template, split_template
from crypto_engine import encrypt_fragment, decrypt_fragment, hash_data

# 1. Simulate capture
user_id = "user_999"
master_template = generate_biometric_template(user_id)
print(f"Generated 128D Template for {user_id}. Vector length: {len(master_template['features'])}")

# 2. Fragment the data
frag_a, frag_b = split_template(master_template)
print(f"Fragment A length: {len(frag_a['features'])} | Fragment B length: {len(frag_b['features'])}")

# 3. Encrypt the fragments with their respective keys
encrypted_frag_a = encrypt_fragment(CLIENT_KEY, frag_a)
encrypted_frag_b = encrypt_fragment(SERVER_KEY, frag_b)
print("\nEncryption Successful (AES-256 GCM).")
print(f"Encrypted Frag A (Hex): {encrypted_frag_a.hex()[:50]}...")
print(f"Encrypted Frag B (Hex): {encrypted_frag_b.hex()[:50]}...")

# 4. SHA-256 Hashing Example (can be used to verify integrity later)
frag_b_hash = hash_data(str(frag_b))
print(f"SHA-256 Hash of Fragment B: {frag_b_hash}")

# 5. Test Decryption (Simulating the client retrieving Frag B in Phase 4)
decrypted_frag_b = decrypt_fragment(SERVER_KEY, encrypted_frag_b)
print(f"\nDecryption Successful. Recovered Fragment B length: {len(decrypted_frag_b['features'])}")