import uvicorn
from api.api import app
from api.pylibs.auth_db import init_db

if __name__ == "__main__":
    # Initialize database
    init_db()
    
    # Run server
    uvicorn.run(
        "api.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    ) 