import asyncio
import os
from dotenv import load_dotenv
from resume_analysis.models.enhanced_resume_scorer import EnhancedResumeScorer
from resume_analysis.config import Config

async def test_resume_analysis():
    load_dotenv()
    
    # Create a simple test resume
    test_resume = """
    JOHN DOE
    Software Engineer
    
    SKILLS
    Python, JavaScript, Machine Learning
    
    EXPERIENCE
    Senior Developer at Tech Corp
    - Led team of 5 developers
    - Implemented ML pipeline
    """
    
    config = Config()
    scorer = EnhancedResumeScorer(config)
    
    try:
        analysis = await scorer.analyze_profile(
            resume_pdf=test_resume.encode(),
            github_username="example_user"
        )
        print("Analysis successful!")
        print(analysis)
        return True
    except Exception as e:
        print(f"Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    asyncio.run(test_resume_analysis()) 