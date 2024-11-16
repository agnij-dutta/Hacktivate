from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from ..models import HackathonCreate, Application
from ..pylibs.auth_db import get_current_user, verify_organizer

router = APIRouter()

@router.post("/hackathons/create")
async def create_hackathon(
    hackathon: HackathonCreate,
    current_user = Depends(verify_organizer)
):
    # Create hackathon in database
    hackathon_id = await db.hackathons.insert_one({
        **hackathon.dict(),
        "organizer_id": current_user["id"],
        "created_at": datetime.utcnow()
    })
    
    return {"hackathon_id": str(hackathon_id.inserted_id)}

@router.post("/hackathons/{hackathon_id}/apply")
async def apply_to_hackathon(
    hackathon_id: str,
    application: Application,
    current_user = Depends(get_current_user)
):
    # Verify hackathon exists
    hackathon = await db.hackathons.find_one({"_id": ObjectId(hackathon_id)})
    if not hackathon:
        raise HTTPException(status_code=404, detail="Hackathon not found")
    
    # Handle application
    if application.apply_type == ApplyType.QUICK:
        if not hackathon["quick_apply_enabled"]:
            raise HTTPException(status_code=400, detail="Quick apply not enabled")
            
        # Create application record
        await db.applications.insert_one({
            "profile_id": application.profile_id,
            "hackathon_id": hackathon_id,
            "type": "quick",
            "status": "pending",
            "created_at": datetime.utcnow()
        })
        
        return {"status": "Application submitted"}
    else:
        # Redirect to external URL
        return {"redirect_url": hackathon["external_url"]}

@router.get("/hackathons/{hackathon_id}/applications")
async def view_applications(
    hackathon_id: str,
    current_user = Depends(verify_organizer)
):
    # Verify ownership
    hackathon = await db.hackathons.find_one({
        "_id": ObjectId(hackathon_id),
        "organizer_id": current_user["id"]
    })
    if not hackathon:
        raise HTTPException(status_code=404, detail="Hackathon not found")
    
    # Get applications with profiles
    applications = await db.applications.aggregate([
        {"$match": {"hackathon_id": hackathon_id}},
        {"$lookup": {
            "from": "profiles",
            "localField": "profile_id",
            "foreignField": "_id",
            "as": "profile"
        }}
    ]).to_list(None)
    
    return {"applications": applications}

@router.post("/hackathons/{hackathon_id}/applications/{application_id}/approve")
async def approve_application(
    hackathon_id: str,
    application_id: str,
    current_user = Depends(verify_organizer)
):
    # Update application status
    result = await db.applications.update_one(
        {
            "_id": ObjectId(application_id),
            "hackathon_id": hackathon_id
        },
        {"$set": {"status": "approved"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Application not found")
    
    return {"status": "Application approved"} 