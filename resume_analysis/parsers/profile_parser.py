from typing import Dict, Optional, List
import PyPDF2
import io
from github import Github
from linkedin import linkedin
from datetime import datetime 
import re

class ProfileParser:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.github_token = self.config.get('github_token')
        self.linkedin_api = None
        if self.config.get('linkedin_token'):
            self._initialize_linkedin()
    
    async def parse_all_sources(self, 
                              resume_pdf: bytes,
                              github_username: Optional[str] = None,
                              linkedin_url: Optional[str] = None) -> str:
        """Parse and concatenate all available profile sources"""
        sections = []
        
        # Parse PDF Resume
        if resume_pdf:
            resume_text = await self._parse_resume_pdf(resume_pdf)
            sections.append(f"RESUME SECTION:\n{resume_text}")
        
        # Parse GitHub Profile
        if github_username and self.github_token:
            github_text = await self._parse_github_profile(github_username)
            sections.append(f"GITHUB SECTION:\n{github_text}")
            
        # Parse LinkedIn Profile
        if linkedin_url and self.linkedin_api:
            linkedin_text = await self._parse_linkedin_profile(linkedin_url)
            sections.append(f"LINKEDIN SECTION:\n{linkedin_text}")
            
        # Combine all sections with clear separators
        return "\n\n" + "\n\n===\n\n".join(sections) + "\n"
    
    async def _parse_resume_pdf(self, pdf_bytes: bytes) -> str:
        """Extract and clean text from PDF resume"""
        try:
            pdf_file = io.BytesIO(pdf_bytes)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            
            # Clean extracted text
            text = self._clean_text(text)
            return text
            
        except Exception as e:
            raise ValueError(f"Failed to parse PDF resume: {str(e)}")
    
    async def _parse_github_profile(self, username: str) -> str:
        """Extract relevant information from GitHub profile"""
        try:
            g = Github(self.github_token)
            user = g.get_user(username)
            repos = user.get_repos()
            
            text = f"GitHub Profile - {username}\n"
            text += f"Bio: {user.bio or ''}\n\n"
            
            # Collect languages and topics
            languages = set()
            topics = set()
            repo_texts = []
            
            for repo in repos:
                if not repo.fork:  # Skip forked repositories
                    if repo.language:
                        languages.add(repo.language)
                    topics.update(repo.get_topics())
                    
                    # Get detailed repo info
                    repo_text = f"Repository: {repo.name}\n"
                    repo_text += f"Description: {repo.description or 'No description'}\n"
                    repo_text += f"Language: {repo.language or 'Not specified'}\n"
                    repo_text += f"Stars: {repo.stargazers_count}\n"
                    repo_text += f"Topics: {', '.join(repo.get_topics())}\n"
                    repo_texts.append(repo_text)
            
            # Add summary sections
            text += f"Programming Languages: {', '.join(languages)}\n"
            text += f"Topics & Skills: {', '.join(topics)}\n\n"
            text += "Notable Repositories:\n"
            text += "\n---\n".join(repo_texts[:5])  # Include top 5 repos
            
            return text
            
        except Exception as e:
            raise ValueError(f"Failed to parse GitHub profile: {str(e)}")
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize extracted text"""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s.,;:!?-]', '', text)
        
        # Normalize line endings
        text = text.replace('\r', '\n')
        text = re.sub(r'\n\s*\n+', '\n\n', text) 
        
        return text.strip()
    
    def _initialize_linkedin(self):
        """Initialize LinkedIn API client"""
        try:
            application = linkedin.LinkedInApplication(
                token=self.linkedin_token
            )
            self.linkedin_api = application
        except Exception as e:
            print(f"Warning: Failed to initialize LinkedIn API: {str(e)}")
            self.linkedin_api = None
    
    async def _parse_linkedin_profile(self, profile_url: str) -> str:
        """Extract relevant information from LinkedIn profile using python3-linkedin"""
        if not self.linkedin_api:
            raise ValueError("LinkedIn API not initialized")
            
        try:
            # Extract profile ID from URL
            profile_id = self._extract_profile_id(profile_url)
            
            # Get basic profile information
            profile = self.linkedin_api.get_profile(selectors=[
                'id', 'first-name', 'last-name', 'headline',
                'industry', 'summary', 'specialties',
                'positions', 'educations', 'skills'
            ])
            
            # Format the extracted information
            text = "LINKEDIN SECTION\n"
            text += f"Name: {profile.get('firstName', '')} {profile.get('lastName', '')}\n"
            text += f"Headline: {profile.get('headline', '')}\n"
            text += f"Industry: {profile.get('industry', '')}\n\n"
            
            # Add summary if available
            if profile.get('summary'):
                text += f"Summary:\n{profile['summary']}\n\n"
            
            # Add positions
            text += "Experience:\n"
            for position in profile.get('positions', {}).get('values', []):
                company = position.get('company', {}).get('name', 'Unknown Company')
                title = position.get('title', 'Unknown Title')
                start_date = self._format_date(position.get('startDate', {}))
                end_date = self._format_date(position.get('endDate', {})) or 'Present'
                
                text += f"- {title} at {company}\n"
                text += f"  {start_date} - {end_date}\n"
                if position.get('summary'):
                    text += f"  {position['summary']}\n"
                text += "\n"
            
            # Add education
            text += "Education:\n"
            for education in profile.get('educations', {}).get('values', []):
                school = education.get('schoolName', '')
                degree = education.get('degree', '')
                field = education.get('fieldOfStudy', '')
                text += f"- {degree} in {field} from {school}\n"
            
            # Add skills
            text += "\nSkills:\n"
            for skill in profile.get('skills', {}).get('values', []):
                text += f"- {skill.get('skill', {}).get('name', '')}\n"
                
            return text
            
        except Exception as e:
            raise ValueError(f"Failed to parse LinkedIn profile: {str(e)}")
    
    def _extract_profile_id(self, profile_url: str) -> str:
        """Extract LinkedIn profile ID from URL"""
        try:
            # Handle different URL formats
            if '/in/' in profile_url:
                return profile_url.split('/in/')[-1].split('/')[0]
            elif '/pub/' in profile_url:
                return profile_url.split('/pub/')[-1].split('/')[0]
            else:
                raise ValueError("Invalid LinkedIn profile URL format")
        except Exception:
            raise ValueError("Could not extract profile ID from URL")
    
    def _format_date(self, date_dict: Dict) -> str:
        """Format LinkedIn date dictionary to string"""
        if not date_dict:
            return ""
        
        try:
            month = str(date_dict.get('month', 1)).zfill(2)
            year = str(date_dict.get('year', ''))
            return f"{month}/{year}"
        except Exception:
            return "" 