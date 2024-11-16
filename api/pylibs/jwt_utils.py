import jwt
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = "your-secret-key"  # Move to environment variables in production
ALGORITHM = "HS256"

def create_jwt_token(email: str) -> str:
    expires_delta = timedelta(days=1)
    expire = datetime.utcnow() + expires_delta
    
    to_encode = {
        "sub": email,
        "exp": expire
    }
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except jwt.JWTError:
        return None 