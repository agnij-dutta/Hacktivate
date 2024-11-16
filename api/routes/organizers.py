from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from typing import Optional, List
from datetime import datetime
from ..models import HackathonCreate, HackathonUpdate, OrganizerDashboard
from ..pylibs.auth_db import verify_organizer
from ..pylibs.db import db
from resume_analysis.models.hackathon_matcher import HackathonMatcher

router = APIRouter()

@router.get("/dashboard")
async def get_organizer_dashboard(current_user = Depends(verify_organizer)):
    """Get organizer's dashboard data"""
    hackathons = db.get_organizer_hackathons(current_user["id"])
    
    dashboard_data = []
    for hackathon in hackathons:
        applications = db.get_hackathon_applications(hackathon["id"])
        
        # Calculate statistics
        total_applications = len(applications)
        approved_applications = sum(1 for app in applications if app["status"] == "approved")
        pending_applications = sum(1 for app in applications if app["status"] == "pending")
        
        # Get average compatibility score
        compatibility_scores = [
            app.get("analysis_results", {}).get("compatibility_score", 0) 
            for app in applications
        ]
        avg_compatibility = sum(compatibility_scores) / len(compatibility_scores) if compatibility_scores else 0
        
        dashboard_data.append({
            "hackathon": hackathon,
            "stats": {
                "total_applications": total_applications,
                "approved_applications": approved_applications,
                "pending_applications": pending_applications,
                "avg_compatibility": round(avg_compatibility, 2)
            }
        })
    
    return {"dashboard": dashboard_data}

@router.post("/hackathons")
async def create_hackathon(
    hackathon: HackathonCreate,
    current_user = Depends(verify_organizer)
):
    """Create a new hackathon"""
    try:
        hackathon_id = db.create_hackathon(
            organizer_id=current_user["id"],
            name=hackathon.name,
            description=hackathon.description,
            primary_track=hackathon.primary_track,
            difficulty=hackathon.difficulty,
            start_date=hackathon.start_date,
            end_date=hackathon.end_date,
            application_deadline=hackathon.application_deadline,
            prize_pool=hackathon.prize_pool,
            external_url=hackathon.external_url,
            quick_apply_enabled=hackathon.quick_apply_enabled
        )
        return {"hackathon_id": hackathon_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/hackathons/{hackathon_id}/applicants")
async def get_hackathon_applicants(
    hackathon_id: int,
    current_user = Depends(verify_organizer)
):
    """Get detailed applicant information for a hackathon"""
    # Verify ownership
    hackathon = db.get_hackathon(hackathon_id)
    if not hackathon or hackathon["organizer_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Hackathon not found")
    
    applications = db.get_hackathon_applications(hackathon_id)
    
    # Enhance with compatibility scores
    matcher = HackathonMatcher()
    for app in applications:
        app["compatibility"] = matcher.calculate_compatibility(
            app["analysis_results"],
            hackathon
        )
    
    return {
        "hackathon": hackathon,
        "applications": sorted(
            applications,
            key=lambda x: x["compatibility"]["score"],
            reverse=True
        )
    } 