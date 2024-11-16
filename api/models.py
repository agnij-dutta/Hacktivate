from pydantic import BaseModel
from typing import Optional, List, Dict
from enum import Enum

class ApplyType(str, Enum):
    QUICK = "quick"
    NORMAL = "normal"

class ProfileCreate(BaseModel):
    name: str
    email: str
    github_username: Optional[str]
    linkedin_url: Optional[str]
    resume_file: bytes
    linkedin_file: Optional[bytes]

class HackathonCreate(BaseModel):
    name: str
    description: str
    start_date: str
    end_date: str
    primary_track: str
    difficulty: str
    prize_pool: Optional[float]
    external_url: Optional[str]
    organizer_email: str
    quick_apply_enabled: bool = False
    application_deadline: str

class Application(BaseModel):
    profile_id: str
    hackathon_id: str
    apply_type: ApplyType
    status: str = "pending" 