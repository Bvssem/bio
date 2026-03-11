# database.py
import sqlite3

DB_NAME = "biometrics.db"

def init_db():
    """Initializes the SQLite database and creates the users table."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            encrypted_fragment_b BLOB
        )
    ''')
    conn.commit()
    conn.close()

def store_fragment(user_id: str, encrypted_fragment: bytes):
    """Stores or updates the encrypted Fragment B in the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO users (user_id, encrypted_fragment_b) 
        VALUES (?, ?)
    ''', (user_id, encrypted_fragment))
    conn.commit()
    conn.close()

def get_fragment(user_id: str) -> bytes:
    """Retrieves the encrypted Fragment B from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_fragment_b FROM users WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None