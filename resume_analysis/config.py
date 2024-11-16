from pydantic import BaseSettings
import os

class Config(BaseSettings):
    HUGGINGFACE_TOKEN: str
    GITHUB_TOKEN: str | None = None
    LINKEDIN_TOKEN: str | None = None
    LINKEDIN_CLIENT_ID: str | None = None
    LINKEDIN_CLIENT_SECRET: str | None = None
    MAX_REQUESTS_PER_MINUTE: int = 60
    MODEL_NAME: str = "meta-llama/Llama-2-7b-chat-hf"
    CACHE_TTL: int = 3600
    
    class Config:
        env_file = ".env" 