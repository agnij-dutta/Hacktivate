import sqlite3
import hashlib
import os
from typing import Optional, Dict
from .db import get_db, hash_password
from .jwt_utils import verify_jwt_token
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from datetime import datetime, timedelta
from ..pylibs.db import db

# Database setup
DB_NAME = 'auth_data.db'

def create_table():
    """Create users table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
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

def register(username, password):
    """
    Register a new user.
    Stores the username, hashed password, and salt in the database.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        salt, password_hash = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                       (username, password_hash, salt))
        conn.commit()
        print(f"User '{username}' registered successfully.")
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
    finally:
        conn.close()

def authenticate(username, password):
    """
    Authenticate a user.
    Verifies the username and password against stored credentials.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        print("Authentication failed: Username not found.")
        return False

    stored_hash, salt = result
    _, input_hash = hash_password(password, salt)

    if input_hash == stored_hash:
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed: Incorrect password.")
        return False

def verify_organizer(email: str) -> bool:
    """
    Verifies if a user is an organizer by checking their account type
    Returns True if user exists and is an organizer, False otherwise
    """
    user = get_user(email)
    return user is not None and user.get('accountType') == 'organizer'

def get_user(email: str) -> Optional[Dict]:
    """Get user by email"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        return dict(row) if row else None

def verify_password(email: str, password: str) -> bool:
    """Verify password for given email"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, salt FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        
        if not result:
            return False
            
        stored_hash, salt = result
        _, password_hash = hash_password(password, salt)
        return stored_hash == password_hash

def register_user(email: str, password: str, account_type: str, company_name: Optional[str] = None) -> bool:
    """Register a new user"""
    try:
        salt, password_hash = hash_password(password, "")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, salt, account_type, company_name)
                VALUES (?, ?, ?, ?, ?)
                """,
                (email, password_hash, salt, account_type, company_name)
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False

def get_current_user(token: str) -> Optional[Dict]:
    """Get current user from JWT token"""
    email = verify_jwt_token(token)
    if not email:
        return None
    return get_user(email)

def verify_organizer(token: str) -> Optional[Dict]:
    """Verify if user is an organizer"""
    user = get_current_user(token)
    if not user or user["account_type"] != "organizer":
        return None
    return user

SECRET_KEY = "your-secret-key"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = db.get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def verify_organizer(current_user = Depends(get_current_user)):
    if current_user["account_type"] != "company":
        raise HTTPException(status_code=403, detail="Not authorized as organizer")
    return current_user

#