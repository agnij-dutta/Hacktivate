from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from .pylibs.auth import register_user, verify_password, get_user, init_db
from .pylibs.jwt_utils import create_jwt_token, verify_jwt_token
from resume_analysis.models.enhanced_resume_scorer import EnhancedResumeScorer
from resume_analysis.config import Config

app = FastAPI()

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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

async def get_auth_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != 'bearer':
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
        return token
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

@app.post("/api/auth/register")
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

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    if not verify_password(user_data.email, user_data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = get_user(user_data.email)
    token = create_jwt_token(user_data.email)
    return {"token": token, "user": user}

@app.post("/api/analyze-resume")
async def analyze_resume(
    resume_file: UploadFile = File(...),
    github_username: Optional[str] = None,
    token: str = Depends(get_auth_token)
):
    try:
        resume_bytes = await resume_file.read()
        config = Config()
        scorer = EnhancedResumeScorer(config)
        
        analysis = await scorer.analyze_profile(
            resume_pdf=resume_bytes,
            github_username=github_username
        )
        
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/auth/verify")
async def verify_auth(token: str = Depends(get_auth_token)):
    try:
        email = verify_jwt_token(token)
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = get_user(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
            
        return {"verified": True, "user": user}
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication failed")
