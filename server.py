# server.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import datetime
import base64
from contextlib import asynccontextmanager
import database

# --- Configuration ---
JWT_SECRET = "SuperSecretJWTKey123" # Kept clear text for academic simulation
JWT_ALGORITHM = "HS256"
security = HTTPBearer()

# --- Application Startup ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db() # Create DB table on startup
    print("Database initialized.")
    yield

app = FastAPI(title="Zero-Knowledge Biometric Vault", lifespan=lifespan)

# --- Pydantic Data Models ---
class UserLogin(BaseModel):
    username: str
    password: str

class EnrollmentData(BaseModel):
    user_id: str
    encrypted_fragment_b_base64: str

class AuthRequest(BaseModel):
    user_id: str

# --- Security: JWT Verification ---
def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validates the JWT token provided in the Authorization header."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- API Endpoints ---

@app.post("/token")
def login(user: UserLogin):
    """Simulates login to get a JWT token. (Accepts any non-empty credentials)"""
    if user.username and user.password:
        expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        token = jwt.encode({"sub": user.username, "exp": expiration}, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/enroll")
def enroll(data: EnrollmentData, current_user: str = Depends(verify_jwt)):
    """Receives Encrypted Fragment B and stores it in SQLite."""
    try:
        # Decode base64 string back into bytes for SQLite BLOB storage
        encrypted_bytes = base64.b64decode(data.encrypted_fragment_b_base64)
        database.store_fragment(data.user_id, encrypted_bytes)
        return {"message": "Fragment B successfully secured in vault."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/retrieve")
def retrieve(data: AuthRequest, current_user: str = Depends(verify_jwt)):
    """Fetches Encrypted Fragment B for the Zero-Knowledge Authentication Flow."""
    encrypted_bytes = database.get_fragment(data.user_id)
    if not encrypted_bytes:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Encode bytes back to base64 for JSON transport
    b64_fragment = base64.b64encode(encrypted_bytes).decode('utf-8')
    return {"user_id": data.user_id, "encrypted_fragment_b_base64": b64_fragment}

# Add this to the very bottom of server.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)