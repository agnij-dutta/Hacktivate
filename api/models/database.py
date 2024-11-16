from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
from enum import Enum

class ProfileStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"

class ApplicationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class HackathonStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    CLOSED = "closed"

class Profile(BaseModel):
    id: int
    user_id: int
    name: str
    github_username: Optional[str]
    linkedin_url: Optional[str]
    resume_path: str
    linkedin_path: Optional[str]
    analysis_results: Dict
    status: ProfileStatus
    created_at: datetime
    updated_at: datetime

class Hackathon(BaseModel):
    id: int
    organizer_id: int
    name: str
    description: str
    primary_track: str
    difficulty: str
    start_date: datetime
    end_date: datetime
    application_deadline: datetime
    prize_pool: Optional[float]
    external_url: Optional[str]
    quick_apply_enabled: bool
    status: HackathonStatus
    created_at: datetime 