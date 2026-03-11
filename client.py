# client.py
import requests
import base64
import json
import math
import random
from config import CLIENT_KEY, SERVER_KEY, SEUIL
from biometrics import generate_biometric_template, split_template
from crypto_engine import encrypt_fragment, decrypt_fragment

BASE_URL = "http://127.0.0.1:8000"

# --- Math Helper for Phase 4 ---
def cosine_distance(vec1: list, vec2: list) -> float:
    """Calculates the cosine distance between two numerical vectors."""
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    mag1 = math.sqrt(sum(a * a for a in vec1))
    mag2 = math.sqrt(sum(b * b for b in vec2))
    
    if mag1 == 0 or mag2 == 0:
        return 1.0 # Maximum distance if one vector is empty
        
    cosine_similarity = dot_product / (mag1 * mag2)
    return 1.0 - cosine_similarity

def simulate_new_capture(original_features: list, is_imposter: bool = False) -> list:
    """Simulates a new biometric scan at authentication time."""
    if is_imposter:
        # Complete mismatch (Random 128D vector)
        return[round(random.uniform(0.0, 1.0), 6) for _ in range(128)]
    
    # Legitimate user: adds very slight noise to simulate natural sensor variations
    noise_level = 0.05
    return[max(0.0, min(1.0, val + random.uniform(-noise_level, noise_level))) for val in original_features]

# --- API Interaction ---
def get_jwt_token():
    print("1. Requesting JWT Token...")
    response = requests.post(f"{BASE_URL}/token", json={"username": "admin", "password": "password"})
    response.raise_for_status()
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def run_zero_knowledge_flow(user_id: str):
    headers = get_jwt_token()
    
    # ==========================================
    # STEP A: ENROLLMENT (Data Creation & Split)
    # ==========================================
    print(f"\n--- ENROLLMENT PHASE for {user_id} ---")
    master_template = generate_biometric_template(user_id)
    frag_a, frag_b = split_template(master_template)
    
    # Encrypt Fragments
    enc_frag_a = encrypt_fragment(CLIENT_KEY, frag_a)
    enc_frag_b = encrypt_fragment(SERVER_KEY, frag_b)
    
    # Save Fragment A locally (simulating secure enclave on device)
    with open("local_fragment_a.bin", "wb") as f:
        f.write(enc_frag_a)
    print("2. Encrypted Fragment A saved securely on local device.")
    
    # Send Fragment B to the Server Vault
    b64_frag_b = base64.b64encode(enc_frag_b).decode('utf-8')
    payload = {"user_id": user_id, "encrypted_fragment_b_base64": b64_frag_b}
    enroll_resp = requests.post(f"{BASE_URL}/enroll", json=payload, headers=headers)
    print(f"3. Server Response: {enroll_resp.json()['message']}")
    
    # ==========================================
    # STEP B: AUTHENTICATION (Zero-Knowledge)
    # ==========================================
    print(f"\n--- AUTHENTICATION PHASE for {user_id} ---")
    
    # 4. Simulate a new physical scan on the device
    print("4. Capturing new biometric scan on device...")
    new_capture_vector = simulate_new_capture(master_template["features"], is_imposter=False)
    
    # 5. Fetch Encrypted Fragment B from Server
    print("5. Requesting Encrypted Fragment B from Server Vault...")
    retrieve_resp = requests.post(f"{BASE_URL}/retrieve", json={"user_id": user_id}, headers=headers)
    retrieved_b64 = retrieve_resp.json()["encrypted_fragment_b_base64"]
    retrieved_enc_frag_b = base64.b64decode(retrieved_b64)
    
    # 6. Decrypt both fragments locally
    print("6. Decrypting both fragments locally...")
    with open("local_fragment_a.bin", "rb") as f:
        local_enc_frag_a = f.read()
    
    decrypted_frag_a = decrypt_fragment(CLIENT_KEY, local_enc_frag_a)
    decrypted_frag_b = decrypt_fragment(SERVER_KEY, retrieved_enc_frag_b)
    
    # 7. Recombine and Calculate Math
    print("7. Recombining Master Template on client...")
    recombined_vector = decrypted_frag_a["features"] + decrypted_frag_b["features"]
    
    print("8. Calculating Cosine Distance against new capture...")
    distance = cosine_distance(new_capture_vector, recombined_vector)
    
    # 8. Validation
    print(f"\n--- RESULTS ---")
    print(f"Calculated Cosine Distance: {distance:.4f}")
    print(f"System Threshold (SEUIL)  : {SEUIL}")
    
    if distance < SEUIL:
        print("✅ SUCCESS: Distance is strictly less than threshold. User Authenticated!")
        print("Notice: The server NEVER saw the recombined vector or Fragment A.")
    else:
        print("❌ DENIED: Distance exceeds threshold. Authentication failed.")

if __name__ == "__main__":
    run_zero_knowledge_flow("Hela_User_001")