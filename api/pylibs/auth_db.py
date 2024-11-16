import sqlite3
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
from passlib.context import CryptContext
from datetime import datetime
import os
from contextlib import contextmanager

# Constants
DATABASE_PATH = "hacktivate.db"
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key")  # Use environment variable in production
ALGORITHM = "HS256"

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                account_type TEXT NOT NULL,
                company_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                name TEXT,
                github_username TEXT,
                linkedin_url TEXT,
                resume_path TEXT,
                linkedin_path TEXT,
                analysis_results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS hackathons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organizer_id INTEGER,
                name TEXT NOT NULL,
                description TEXT,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                application_deadline TIMESTAMP,
                primary_track TEXT,
                difficulty TEXT,
                prize_pool REAL,
                external_url TEXT,
                quick_apply_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organizer_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER,
                hackathon_id INTEGER,
                apply_type TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES profiles(id),
                FOREIGN KEY (hackathon_id) REFERENCES hackathons(id)
            );
        """)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user(email: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            return dict(user)
    return None

def get_user_by_id(user_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return dict(user)
    return None

def register_user(email: str, password: str, account_type: str, company_name: str = None) -> bool:
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            hashed_password = get_password_hash(password)
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, account_type, company_name)
                VALUES (?, ?, ?, ?)
                """,
                (email, hashed_password, account_type, company_name)
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False

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
    user = get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def verify_organizer(current_user = Depends(get_current_user)):
    if current_user["account_type"] != "company":
        raise HTTPException(status_code=403, detail="Not authorized as organizer")
    return current_user

#