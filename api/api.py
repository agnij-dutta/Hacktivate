from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import auth, profiles, hackathons, applications
from .pylibs.db import init_db

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(profiles.router, prefix="/api/profiles", tags=["profiles"])
app.include_router(hackathons.router, prefix="/api/hackathons", tags=["hackathons"])
app.include_router(applications.router, prefix="/api/applications", tags=["applications"])
