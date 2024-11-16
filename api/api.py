from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from .pylibs.auth import register as auth_register, verify_password, create_jwt_token

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    accountType: str
    companyName: Optional[str] = None

@app.post("/auth/login")
async def login(user_data: UserLogin):
    try:
        # Verify user credentials
        if not verify_password(user_data.email, user_data.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Generate JWT token
        token = create_jwt_token(user_data.email)
        
        return {"token": token, "email": user_data.email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/register")
async def register(user_data: UserRegister):
    try:
        # Register new user
        auth_register(user_data.email, user_data.password)
        
        # Generate JWT token
        token = create_jwt_token(user_data.email)
        
        return {"token": token, "email": user_data.email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
