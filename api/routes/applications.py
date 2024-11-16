from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from ..models import ApplicationStatus
from ..pylibs.auth_db import get_current_user, verify_organizer
from ..pylibs.db import db
from datetime import datetime

router = APIRouter()

@router.get("/applications/me")
async def get_my_applications(current_user = Depends(get_current_user)):
    """Get all applications for the current user"""
    applications = await db.applications.find({
        "user_id": current_user["id"]
    }).to_list(None)
    
    return {"applications": applications}

@router.get("/applications/{application_id}")
async def get_application(
    application_id: str,
    current_user = Depends(get_current_user)
):
    """Get specific application details"""
    application = await db.applications.find_one({
        "_id": application_id,
        "user_id": current_user["id"]
    })
    
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    return application

@router.put("/applications/{application_id}/withdraw")
async def withdraw_application(
    application_id: str,
    current_user = Depends(get_current_user)
):
    """Withdraw an application"""
    result = await db.applications.update_one(
        {
            "_id": application_id,
            "user_id": current_user["id"],
            "status": {"$nin": ["withdrawn", "rejected"]}
        },
        {"$set": {"status": "withdrawn"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=400, 
            detail="Application cannot be withdrawn"
        )
    
    return {"status": "Application withdrawn"}

@router.put("/applications/{application_id}/status")
async def update_application_status(
    application_id: str,
    status: ApplicationStatus,
    current_user = Depends(verify_organizer)
):
    """Update application status (organizer only)"""
    # Verify organizer owns the hackathon
    application = await db.applications.find_one({"_id": application_id})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
        
    hackathon = await db.hackathons.find_one({
        "_id": application["hackathon_id"],
        "organizer_id": current_user["id"]
    })
    if not hackathon:
        raise HTTPException(
            status_code=403, 
            detail="Not authorized to update this application"
        )
    
    # Update status
    result = await db.applications.update_one(
        {"_id": application_id},
        {"$set": {
            "status": status,
            "updated_at": datetime.utcnow()
        }}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=400, 
            detail="Failed to update application status"
        )
    
    return {"status": "Application status updated"}
