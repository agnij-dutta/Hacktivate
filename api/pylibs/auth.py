import sqlite3
import hashlib
import os
from typing import Optional, Dict

DB_NAME = 'auth_data.db'

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            account_type TEXT NOT NULL,
            company_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_user(email: str) -> Optional[Dict]:
    """Get user details from database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'email': user[1],
            'account_type': user[4],
            'company_name': user[5]
        }
    return None

def verify_password(email: str, password: str) -> bool:
    """Verify password for given email"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, salt FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
        
    stored_hash, salt = result
    _, password_hash = hash_password(password, salt)
    return stored_hash == password_hash

def register_user(email: str, password: str, account_type: str, company_name: Optional[str] = None) -> bool:
    """Register a new user"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        salt, password_hash = hash_password(password)
        cursor.execute(
            'INSERT INTO users (email, password_hash, salt, account_type, company_name) VALUES (?, ?, ?, ?, ?)',
            (email, password_hash, salt, account_type, company_name)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def hash_password(password, salt=None):
    """
    Hash a password with an optional salt.
    If no salt is provided, generate a new one.
    Returns the salt and hashed password.
    """
    if not salt:
        salt = os.urandom(16).hex()
    salted_password = f"{password}{salt}"
    password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
    return salt, password_hash

#