import sqlite3
import hashlib
import os

# Database setup
DB_NAME = './databases/auth_data.db'

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

def verify_password(username: str, password: str) -> bool:
    """Verify a user's password."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        if not result:
            return False
            
        stored_hash, salt = result
        _, password_hash = hash_password(password, salt)
        return password_hash == stored_hash
    finally:
        conn.close()

#