import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from dotenv import load_dotenv
from resume_analysis.models.enhanced_resume_scorer import EnhancedResumeScorer
from resume_analysis.models.hackathon_matcher import HackathonMatcher
from typing import List, Dict, Optional
import json
from resume_analysis.utils.rate_limiter import RateLimiter
from resume_analysis.config import Config
from resume_analysis.parsers.profile_parser import ProfileParser
import asyncio

# Load environment variables
load_dotenv()

def initialize_llm():
    """Initialize LLM with environment variables and validate tokens"""
    try:
        huggingface_token = os.getenv('HUGGINGFACE_TOKEN')
        if not huggingface_token:
            raise ValueError("HUGGINGFACE_TOKEN not found in environment variables")
        
        # Test connection by making a simple request
        response = requests.post(
            "https://api-inference.huggingface.co/models/facebook/opt-350m",
            headers={"Authorization": f"Bearer {huggingface_token}"},
            json={"inputs": "Test connection"}
        )
        
        if response.status_code == 200:
            print("Successfully initialized Hugging Face client")
            return True
            
        raise ValueError(f"API test failed with status code: {response.status_code}")
        
    except Exception as e:
        print(f"Error initializing LLM: {str(e)}")
        print("\nPlease ensure you have:")
        print("1. Set the HUGGINGFACE_TOKEN environment variable")
        print("2. Created an API token at https://huggingface.co/settings/tokens")
        return False

async def analyze_candidate(
    resume_pdf: bytes,
    github_username: Optional[str] = None,
    linkedin_url: Optional[str] = None,
    hackathons: Optional[List[Dict]] = None
) -> Dict:
    """
    Analyze a candidate's profile and match with hackathons
    """
    try:
        if not initialize_llm():
            raise RuntimeError("Failed to initialize LLM")
            
        config = Config()
        scorer = EnhancedResumeScorer(config)
        
        # Analyze profile
        analysis = await scorer.analyze_profile(
            resume_pdf,
            github_username,
            linkedin_url
        )
        
        # Match with hackathons if provided
        if hackathons:
            matcher = HackathonMatcher()
            matches = matcher.match_hackathons(analysis, hackathons)
            analysis['hackathon_matches'] = matches
            
        return analysis
        
    except Exception as e:
        print(f"Error in analyze_candidate: {str(e)}")
        raise

async def analyze_linkedin_profile(pdf_file_content: bytes) -> Dict:
    parser = ProfileParser()
    try:
        profile_data = await parser.parse_linkedin_pdf(pdf_file_content)
        
        # Add any additional analysis here
        analysis_results = {
            'profile_data': profile_data,
            'analysis': {
                'skills_match': analyze_skills(profile_data['skills']),
                'experience_level': analyze_experience(profile_data['experience']),
                'education_level': analyze_education(profile_data['education'])
            }
        }
        
        return analysis_results
    except Exception as e:
        raise ValueError(f"Failed to analyze LinkedIn profile: {str(e)}")

if __name__ == "__main__":
    # Example usage
    try:
        with open("example_resume.pdf", "rb") as f:
            resume_pdf = f.read()
            
        results = asyncio.run(analyze_candidate(
            resume_pdf=resume_pdf,
            github_username="example_user",
            hackathons=[{
                "id": "1",
                "name": "Example Hackathon",
                "primary_track": "ai_ml",
                "difficulty": "Intermediate"
            }]
        ))
        
        print(json.dumps(results, indent=2))
        
    except FileNotFoundError:
        print("Please provide a valid resume PDF file")
    except Exception as e:
        print(f"Error: {str(e)}") 