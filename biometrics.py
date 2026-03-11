# biometrics.py
import time
import random

def generate_biometric_template(user_id: str) -> dict:
    """Simulates a 128D numerical vector capture."""
    # Generate 128 random floats between 0.0 and 1.0 to simulate biometric features
    vector =[round(random.uniform(0.0, 1.0), 6) for _ in range(128)]
    
    template = {
        "user_id": user_id,
        "features": vector,
        "timestamp": int(time.time()),
        "version": "1.0"
    }
    return template

def split_template(template: dict):
    """Fragments the 128D vector into Fragment A (0-63) and Fragment B (64-127)."""
    features = template["features"]
    
    # Fragment A: Stays on Client
    fragment_a = template.copy()
    fragment_a["features"] = features[:64] 
    
    # Fragment B: Sent to Server
    fragment_b = template.copy()
    fragment_b["features"] = features[64:] 
    
    return fragment_a, fragment_b