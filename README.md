# SecurPrint — Zero-Knowledge Biometric Vault

> A split-template biometric authentication system where neither the client nor
> the server ever holds the complete biometric template. Academic
> applied-cryptography project (TEK-UP SSIR track).

## Overview

SecurPrint protects biometric templates by splitting a 128-dimensional feature
vector into two encrypted fragments:

- **Fragment A** (dimensions 0–63) — encrypted with the client key and stored
  locally on the device (`local_fragment_a.bin`), simulating a secure enclave.
- **Fragment B** (dimensions 64–127) — encrypted with the server key and stored
  as a BLOB in a SQLite vault on the server.

The server never sees Fragment A, the client never stores Fragment B in
plaintext, and the full template is only recombined on the client during
authentication. An attacker who compromises the server obtains only encrypted
Fragment B — useless without Fragment A.

## Tech Stack

| Layer | Technology |
|---|---|
| API server | Python · FastAPI · Uvicorn |
| Authentication | JWT (HS256) bearer tokens |
| Encryption | AES-256-GCM (12-byte nonce, authenticated) · SHA-256 |
| Template matching | Cosine distance over 128D vectors, threshold `SEUIL = 0.15` |
| Storage | SQLite (`biometrics.db`) — `users(user_id, encrypted_fragment_b)` |
| HTTP client | Python `requests` |

## Architecture

```
ENROLLMENT
  Client                                Server
  ------                                ------
  generate 128D template (biometrics.py)
  split → Frag A [0:63] | Frag B [64:127]
  encrypt A with CLIENT_KEY (AES-256-GCM)
  save A → local_fragment_a.bin
  encrypt B with SERVER_KEY (AES-256-GCM)
  POST /enroll (base64 B, JWT)   ────►  store BLOB in SQLite

AUTHENTICATION (zero-knowledge)
  Client                                Server
  ------                                ------
  new biometric capture (simulated sensor noise)
  load local Frag A from local_fragment_a.bin
  POST /retrieve (JWT)           ◄────  fetch encrypted BLOB
  decrypt A + B locally
  recombine 128D vector
  cosine_distance(new_capture, recombined)
  distance < 0.15 ?  AUTHENTICATED : DENIED

  ※ The server never sees the recombined vector or Fragment A.
```

## Setup & Usage

```bash
# 1. Install dependencies
pip install fastapi uvicorn pyjwt cryptography requests

# 2. Start the vault server
python server.py          # → http://127.0.0.1:8000

# 3. Run the enrollment + authentication flow
python client.py          # demo user: Hela_User_001
```

### API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/token` | — | Issue a JWT (accepts any non-empty credentials in the simulation) |
| POST | `/enroll` | JWT | Store encrypted Fragment B |
| POST | `/retrieve` | JWT | Fetch encrypted Fragment B |

## File Map

| File | Role |
|---|---|
| `biometrics.py` | Generates the 128D template and splits it into Fragments A/B |
| `crypto_engine.py` | AES-256-GCM encrypt/decrypt + SHA-256 hashing |
| `server.py` | FastAPI vault server with JWT-gated `/enroll` and `/retrieve` |
| `client.py` | Orchestrates enrollment and zero-knowledge authentication |
| `database.py` | SQLite layer for storing/retrieving encrypted Fragment B |
| `config.py` | AES-256 keys and cosine-distance threshold (`SEUIL`) |
| `test.py` | Test harness |

## Security Takeaways

- **Split-template design** — neither side holds the full biometric vector;
  server compromise yields only encrypted Fragment B.
- **Authenticated encryption** — AES-256-GCM provides confidentiality and
  integrity for each fragment.
- **Zero-knowledge matching** — the recombined template and the accept/deny
  decision never leave the client.

### Known limitations (academic simulation)

- Biometric vectors are **simulated** (random 128D floats with sensor-noise
  emulation), not real fingerprint minutiae.
- AES keys (`CLIENT_KEY`, `SERVER_KEY`) and the JWT secret are **hardcoded** in
  `config.py` / `server.py` for the academic simulation. In production these
  must come from a secrets manager or environment variables.
- `biometrics.db` and `local_fragment_a.bin` are gitignored and must never be
  committed — they contain enrolled template material.
