from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..pylibs.auth_db import register_user, verify_password, get_user
from ..pylibs.jwt_utils import create_jwt_token

router = APIRouter()

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    accountType: str
    companyName: Optional[str] = None

@router.post("/register")
async def register(user_data: UserRegister):
    if not register_user(
        user_data.email,
        user_data.password,
        user_data.accountType,
        user_data.companyName
    ):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    token = create_jwt_token(user_data.email)
    return {"token": token, "email": user_data.email}

@router.post("/login")
async def login(user_data: UserLogin):
    if not verify_password(user_data.email, user_data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = get_user(user_data.email)
    token = create_jwt_token(user_data.email)
    return {"token": token, "user": user} 