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


# Load environment variables
load_dotenv()

def initialize_llm():
    """Initialize LLM with environment variables and validate tokens"""
    try:
        huggingface_token = os.getenv('HUGGINGFACE_TOKEN')
        if not huggingface_token:
            raise ValueError("HUGGINGFACE_TOKEN not found in environment variables")
        
        # Validate token
        is_valid, error_message = TokenValidator.validate_huggingface_token(huggingface_token)
        if not is_valid:
            raise ValueError(f"Invalid Hugging Face token: {error_message}")
        
        # Login to Hugging Face
        login(token=huggingface_token)
        print("Successfully initialized LLM with valid token")
        return True
        
    except Exception as e:
        print(f"Error initializing LLM: {str(e)}")
        print("\nPlease ensure you have:")
        print("1. Set the HUGGINGFACE_TOKEN environment variable")
        print("2. Generated a READ token from https://huggingface.co/settings/tokens")
        print("3. Enabled read permissions for the token")
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
    if not os.getenv('HUGGINGFACE_TOKEN') or not os.getenv('GITHUB_TOKEN'):
        print("Please set HUGGINGFACE_TOKEN and GITHUB_TOKEN environment variables")
        exit(1)
    
    # Run analysis
    results = analyze_candidate(
        resume_pdf=sample_resume,
        github_username='example_user',
        linkedin_url='https://www.linkedin.com/in/example_user',
        hackathons=sample_hackathons
    )
    
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