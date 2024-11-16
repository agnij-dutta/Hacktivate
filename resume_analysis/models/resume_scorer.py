from typing import Dict, List
from .skill_extractor import SkillExtractor
from .github_analyzer import GitHubAnalyzer
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class ResumeScorer:
    def __init__(self, github_token: str = None):
        self.skill_extractor = SkillExtractor()
        self.github_analyzer = GitHubAnalyzer(github_token) if github_token else None
        self.domain_weights = {
            'ai_ml': {
                'skills': 0.4,
                'experience': 0.3,
                'github': 0.2,
                'education': 0.1
            },
            'web_dev': {
                'skills': 0.35,
                'experience': 0.25,
                'github': 0.25,
                'education': 0.15
            },
            'blockchain': {
                'skills': 0.4,
                'experience': 0.3, 
                'github': 0.2,
                'education': 0.1
            },
            'cloud': {
                'skills': 0.35,
                'experience': 0.3,
                'github': 0.25,
                'education': 0.1
            },
            'cybersecurity': {
                'skills': 0.35,
                'experience': 0.35,
                'github': 0.2,
                'education': 0.1
            }
        }
        
    def score_resume(self, resume_text: str, github_username: str = None) -> Dict:
        # Extract skills and experience
        skills_analysis = self.skill_extractor.extract_skills(resume_text)
        
        # Get GitHub analysis if available
        github_analysis = None
        if github_username and self.github_analyzer:
            github_analysis = self.github_analyzer.analyze_profile(github_username)
        
        # Calculate domain-specific scores
        domain_scores = {}
        for domain in self.domain_weights.keys():
            domain_scores[domain] = self._calculate_domain_score(
                domain,
                skills_analysis,
                github_analysis
            )
        
        return {
            'domain_scores': domain_scores,
            'skills_analysis': skills_analysis,
            'github_analysis': github_analysis
        }
    
    def _calculate_domain_score(self, domain: str, skills: Dict, github: Dict = None) -> float:
        weights = self.domain_weights[domain]
        score = 0.0
        
        # Calculate skills score
        domain_skills = skills.get(domain, [])
        skills_score = len(domain_skills) * 2  # Scale to 0-10
        score += weights['skills'] * min(skills_score, 10)
        
        # Calculate experience score
        exp_key = f"{domain}_experience"
        experience_score = skills.get(exp_key, 0) * 2  # Scale to 0-10
        score += weights['experience'] * min(experience_score, 10)
        
        # Add GitHub score if available
        if github and 'domain_scores' in github:
            github_score = github['domain_scores'].get(domain, 0)
            score += weights['github'] * github_score
        
        return round(score, 2) 