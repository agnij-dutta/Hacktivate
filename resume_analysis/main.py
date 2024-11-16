import os
from dotenv import load_dotenv
from models.enhanced_resume_scorer import EnhancedResumeScorer
from models.hackathon_matcher import HackathonMatcher
from huggingface_hub import login
from typing import List, Dict, Optional
import json
from utils.token_validator import TokenValidator
from utils.rate_limiter import RateLimiter
from config import Config
from parsers.profile_parser import ProfileParser
import asyncio
from openai import OpenAI


# Load environment variables
load_dotenv()

def initialize_llm():
    """Initialize LLM with environment variables and validate tokens"""
    try:
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        # Initialize OpenAI client
        client = OpenAI(api_key=openai_api_key)
        
        # Test connection with a simple request
        client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "Test connection"}],
            max_tokens=5
        )
        
        print("Successfully initialized OpenAI client")
        return True
        
    except Exception as e:
        print(f"Error initializing LLM: {str(e)}")
        print("\nPlease ensure you have:")
        print("1. Set the OPENAI_API_KEY environment variable")
        print("2. Created an API key at https://platform.openai.com/api-keys")
        return False

async def analyze_candidate(
    resume_pdf: bytes,
    github_username: Optional[str] = None,
    linkedin_url: Optional[str] = None,
    hackathons: Optional[List[Dict]] = None
) -> Dict:
    """
    Analyze candidate profile from multiple sources
    
    Args:
        resume_pdf (bytes): The resume PDF file content
        github_username (str, optional): GitHub username for additional analysis
        linkedin_url (str, optional): LinkedIn profile URL
        hackathons (List[Dict], optional): List of hackathons to match against
    """
    if not resume_pdf:
        raise ValueError("Resume PDF is required")
        
    # Initialize LLM
    if not initialize_llm():
        raise RuntimeError("Failed to initialize LLM")
    
    # Initialize config with all necessary tokens
    config = Config()
    
    # Initialize analyzers
    scorer = EnhancedResumeScorer(config)
    matcher = HackathonMatcher()
    
    try:
        # Get enhanced analysis
        enhanced_analysis = await scorer.analyze_profile(
            resume_pdf,
            github_username,
            linkedin_url
        )
        
        # Match hackathons if provided
        hackathon_matches = None
        if hackathons:
            hackathon_matches = matcher.match_hackathons(
                enhanced_analysis,
                hackathons
            )
        
        return {
            'enhanced_analysis': enhanced_analysis,
            'hackathon_matches': hackathon_matches,
            'source_availability': {
                'github': bool(github_username),
                'linkedin': bool(linkedin_url)
            },
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'enhanced_analysis': None,
            'hackathon_matches': None
        }

if __name__ == "__main__":
    # Example usage
    sample_resume = """
    Machine Learning Engineer with 4 years of experience.
    Proficient in Python, TensorFlow, and PyTorch.
    Led AI projects at Google and Facebook.
    Published research in NLP and Computer Vision.
    Master's degree in Computer Science from Stanford.
    Active open-source contributor.
    """
    
    sample_hackathons = [
        {
            'name': 'AI Breakthrough Hackathon',
            'primary_track': 'ai_ml',
            'tracks': ['ai_ml', 'cloud', 'web_dev'],
            'difficulty': 'Advanced',
            'required_skills': ['python', 'machine-learning', 'deep-learning'],
            'description': 'Focus on breakthrough AI innovations'
        }
    ]
    
    # Ensure environment variables are set
    if not os.getenv('OPENAI_API_KEY') or not os.getenv('GITHUB_TOKEN'):
        print("Please set OPENAI_API_KEY and GITHUB_TOKEN environment variables")
        exit(1)
    
    # Run analysis using asyncio
    results = asyncio.run(analyze_candidate(
        resume_pdf=sample_resume,
        github_username='example_user',
        linkedin_url='https://www.linkedin.com/in/example_user',
        hackathons=sample_hackathons
    ))
    
    # Print results
    if results['status'] == 'success':
        print("Analysis completed successfully!")
        print("\nEnhanced Analysis:")
        print(json.dumps(results['enhanced_analysis'], indent=2))
        if results['hackathon_matches']:
            print("\nHackathon Matches:")
            print(json.dumps(results['hackathon_matches'], indent=2))
    else:
        print(f"Analysis failed: {results['message']}") 