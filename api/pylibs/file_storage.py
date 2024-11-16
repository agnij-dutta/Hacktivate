from pathlib import Path
from fastapi import UploadFile, HTTPException
from typing import Optional
import shutil
import os
from datetime import datetime

UPLOAD_DIR = Path(__file__).parent.parent / "uploads"

async def save_file(file: Optional[UploadFile], folder: str, user_id: int) -> Optional[str]:
    """Save uploaded file and return relative path"""
    if not file:
        return None
        
    # Create upload directories
    save_dir = UPLOAD_DIR / folder / str(user_id)
    save_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{file.filename}"
    file_path = save_dir / filename
    
    # Save file
    try:
        with file_path.open("wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
        
    return str(file_path.relative_to(UPLOAD_DIR))

async def delete_file(file_path: str) -> bool:
    """Delete file from storage"""
    try:
        full_path = UPLOAD_DIR / file_path
        if full_path.exists():
            os.remove(full_path)
            return True
    except Exception:
        pass
    return False 