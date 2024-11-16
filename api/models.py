from enum import Enum
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime

class AccountType(str, Enum):
    PERSONAL = "personal"
    COMPANY = "company"

class ApplyType(str, Enum):
    QUICK = "quick"
    NORMAL = "normal"

class ApplicationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    accountType: AccountType
    companyName: Optional[str] = None

class ProfileCreate(BaseModel):
    name: str
    github_username: Optional[str] = None
    linkedin_url: Optional[str] = None
    resume_file: str  # This will be a file path or file ID
    linkedin_file: Optional[str] = None

class Profile(BaseModel):
    id: str
    user_id: str
    name: str
    github_username: Optional[str] = None
    linkedin_url: Optional[str] = None
    resume_path: str
    linkedin_path: Optional[str] = None
    analysis_results: Optional[Dict] = None
    created_at: datetime

class HackathonCreate(BaseModel):
    name: str
    description: str
    start_date: datetime
    end_date: datetime
    application_deadline: datetime
    primary_track: str
    difficulty: str
    prize_pool: Optional[float] = None
    external_url: Optional[str] = None
    quick_apply_enabled: bool = False

class Hackathon(BaseModel):
    id: str
    organizer_id: str
    name: str
    description: str
    start_date: datetime
    end_date: datetime
    application_deadline: datetime
    primary_track: str
    difficulty: str
    prize_pool: Optional[float] = None
    external_url: Optional[str] = None
    quick_apply_enabled: bool = False
    created_at: datetime

class Application(BaseModel):
    profile_id: str
    apply_type: ApplyType

class ApplicationResponse(BaseModel):
    id: str
    profile_id: str
    hackathon_id: str
    apply_type: ApplyType
    status: ApplicationStatus
    created_at: datetime
    updated_at: Optional[datetime] = None

class AnalysisResults(BaseModel):
    skills: List[str]
    experience_level: str
    education_level: str
    technical_score: float
    domain_scores: Dict[str, float] 