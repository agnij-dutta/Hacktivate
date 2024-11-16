from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from typing import Optional
from ..models import ProfileCreate
from ..pylibs.auth_db import get_current_user
from resume_analysis.main import analyze_candidate
from ..pylibs.db import db
from ..pylibs.file_storage import save_file
from bson.objectid import ObjectId
from datetime import datetime
from resume_analysis.models.hackathon_matcher import HackathonMatcher

router = APIRouter()

@router.post("/profiles/create")
async def create_profile(
    name: str,
    github_username: Optional[str] = None,
    linkedin_url: Optional[str] = None,
    resume_file: UploadFile = File(...),
    linkedin_file: Optional[UploadFile] = File(None),
    current_user = Depends(get_current_user)
):
    try:
        # Save files
        resume_path = await save_file(resume_file, "resumes", current_user["id"])
        linkedin_path = await save_file(linkedin_file, "linkedin", current_user["id"]) if linkedin_file else None
        
        # Analyze profile
        analysis = await analyze_candidate(
            resume_pdf=await resume_file.read(),
            github_username=github_username,
            linkedin_pdf=await linkedin_file.read() if linkedin_file else None
        )
        
        # Create profile
        profile_id = db.create_profile(
            user_id=current_user["id"],
            name=name,
            github_username=github_username,
            linkedin_url=linkedin_url,
            resume_path=resume_path,
            linkedin_path=linkedin_path,
            analysis_results=analysis
        )
        
        return {
            "profile_id": profile_id,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/profiles/{profile_id}/recommendations")
async def get_hackathon_recommendations(
    profile_id: str,
    current_user = Depends(get_current_user)
):
    profile = await db.profiles.find_one({"_id": ObjectId(profile_id)})
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    # Get active hackathons
    hackathons = await db.hackathons.find({
        "application_deadline": {"$gt": datetime.utcnow()}
    }).to_list(None)
    
    # Match hackathons
    matcher = HackathonMatcher()
    matches = matcher.match_hackathons(profile["analysis"], hackathons)
    
    return {"recommendations": matches}

@router.get("/me")
async def get_my_profile(current_user = Depends(get_current_user)):
    profile = await db.get_profile_by_user_id(current_user["id"])
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile 