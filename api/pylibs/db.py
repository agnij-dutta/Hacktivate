import sqlite3
import json
import hashlib
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

DB_PATH = Path(__file__).parent.parent / "data" / "hacktivate.db"
SCHEMA_PATH = Path(__file__).parent / "db_schema.sql"

def generate_salt() -> str:
    return os.urandom(16).hex()

def hash_password(password: str, salt: str) -> tuple[str, str]:
    if not salt:
        salt = generate_salt()
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return salt, key.hex()

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with schema"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    with get_db() as conn:
        with open(SCHEMA_PATH) as f:
            conn.executescript(f.read())
        conn.commit()

class Database:
    @staticmethod
    def create_user(email: str, password: str, account_type: str, company_name: Optional[str] = None) -> int:
        """Create a new user with hashed password"""
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
            return cursor.lastrowid

    @staticmethod
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

    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict]:
        """Get user by email"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def create_profile(
        user_id: int,
        name: str,
        github_username: Optional[str],
        linkedin_url: Optional[str],
        resume_path: str,
        linkedin_path: Optional[str],
        analysis_results: Dict
    ) -> int:
        """Create a new profile and return its ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO profiles (
                    user_id, name, github_username, linkedin_url,
                    resume_path, linkedin_path, analysis_results
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, name, github_username, linkedin_url,
                    resume_path, linkedin_path, json.dumps(analysis_results)
                )
            )
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_profile(profile_id: int) -> Optional[Dict]:
        """Get profile by ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,))
            row = cursor.fetchone()
            if row:
                profile = dict(row)
                profile['analysis_results'] = json.loads(profile['analysis_results'])
                return profile
        return None

    @staticmethod
    def create_hackathon(
        organizer_id: int,
        name: str,
        description: str,
        primary_track: str,
        difficulty: str,
        start_date: str,
        end_date: str,
        application_deadline: str,
        prize_pool: Optional[float] = None,
        external_url: Optional[str] = None,
        quick_apply_enabled: bool = False
    ) -> int:
        """Create a new hackathon and return its ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hackathons (
                    organizer_id, name, description, primary_track,
                    difficulty, start_date, end_date, application_deadline,
                    prize_pool, external_url, quick_apply_enabled
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    organizer_id, name, description, primary_track,
                    difficulty, start_date, end_date, application_deadline,
                    prize_pool, external_url, quick_apply_enabled
                )
            )
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_active_hackathons() -> List[Dict]:
        """Get all active hackathons"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM hackathons 
                WHERE status = 'published' 
                AND application_deadline > datetime('now')
                ORDER BY start_date ASC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def create_application(
        profile_id: int,
        hackathon_id: int,
        apply_type: str
    ) -> int:
        """Create a new application and return its ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (profile_id, hackathon_id, apply_type)
                VALUES (?, ?, ?)
                """,
                (profile_id, hackathon_id, apply_type)
            )
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_hackathon_applications(hackathon_id: int) -> List[Dict]:
        """Get all applications for a hackathon with profile data"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    a.*,
                    p.name as applicant_name,
                    p.github_username,
                    p.linkedin_url,
                    p.analysis_results
                FROM applications a
                JOIN profiles p ON a.profile_id = p.id
                WHERE a.hackathon_id = ?
                ORDER BY a.created_at DESC
                """,
                (hackathon_id,)
            )
            applications = []
            for row in cursor.fetchall():
                app = dict(row)
                app['analysis_results'] = json.loads(app['analysis_results'])
                applications.append(app)
            return applications

    @staticmethod
    def update_application_status(application_id: int, status: str) -> bool:
        """Update application status"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE applications 
                SET status = ?
                WHERE id = ?
                """,
                (status, application_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def get_user_profiles(user_id: int) -> List[Dict]:
        """Get all profiles for a user"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM profiles 
                WHERE user_id = ? 
                ORDER BY created_at DESC
                """,
                (user_id,)
            )
            profiles = []
            for row in cursor.fetchall():
                profile = dict(row)
                profile['analysis_results'] = json.loads(profile['analysis_results'])
                profiles.append(profile)
            return profiles

    @staticmethod
    def get_organizer_hackathons(organizer_id: int) -> List[Dict]:
        """Get all hackathons for an organizer"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM hackathons 
                WHERE organizer_id = ? 
                ORDER BY created_at DESC
                """,
                (organizer_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

# Create a singleton instance
db = Database()