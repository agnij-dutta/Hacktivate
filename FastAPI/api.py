from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import httpx

from pylibs.auth import authenticate, register

register("admin", "password")
authenticate("admin", "password")
authenticate("admin", "wrong_password")
register("admin", "password")

app = FastAPI()

# Replace with your actual backend URL
AUTH_BACKEND_URL = "http://backend-service-url:8000"

# Request Body Models
class SignupRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# Profile Request Body Model
class ProfileRequest(BaseModel):
    username: str
    password: str
    email: str


@app.get("/")
async def root():
    return {"message": "Hello World"}

# Signup Route
@app.post("/auth/signup")
async def signup_user(data: SignupRequest):
    try:
        async with httpx.AsyncClient() as client:
            # Forward the signup request to the backend
            response = await client.post(
                f"{AUTH_BACKEND_URL}/signup", json=data.dict()
            )
            
            if response.status_code != 201:
                raise HTTPException(
                    status_code=response.status_code, detail=response.json().get("detail", "Signup failed")
                )
            return {"message": "User signed up successfully"}
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=str(e))

# Login Route
@app.post("/auth/login")
async def login_user(data: LoginRequest):
    try:
        async with httpx.AsyncClient() as client:
            # Forward the login request to the backend
            response = await client.post(
                f"{AUTH_BACKEND_URL}/login", json=data.dict()
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code, detail=response.json().get("detail", "Login failed")
                )
            
            # Assuming backend sends back a token and user info
            return response.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Profile Creation Route
@app.post("/edit_profile")
async def create_profile(data: ProfileRequest):
    try:
        async with httpx.AsyncClient() as client:
            # Forward the profile creation request to the backend
            response = await client.post(
                f"{AUTH_BACKEND_URL}/profile", json=data.dict()
            )
            
            if response.status_code != 201:
                raise HTTPException(
                    status_code=response.status_code, detail=response.json().get("detail", "Profile creation failed")
                )
            return {"message": "Profile created successfully"}
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=str(e))


# quick apply and apply for the hackathons 
