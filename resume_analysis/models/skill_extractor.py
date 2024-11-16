from typing import List, Dict
import spacy
import re
from collections import defaultdict

class SkillExtractor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.domain_skills = self._load_domain_skills()
        
    def _load_domain_skills(self) -> Dict[str, List[str]]:
        return {
            'ai_ml': [
                'machine learning', 'deep learning', 'neural networks', 'tensorflow',
                'pytorch', 'scikit-learn', 'computer vision', 'nlp', 'data science'
            ],
            'web_dev': [
                'react', 'angular', 'vue', 'nodejs', 'javascript', 'typescript',
                'html', 'css', 'web development', 'frontend', 'backend'
            ],
            'blockchain': [
                'solidity', 'web3', 'ethereum', 'smart contracts', 'defi',
                'blockchain', 'cryptocurrency', 'consensus mechanisms'
            ],
            'cloud': [
                'aws', 'azure', 'gcp', 'docker', 'kubernetes', 'devops',
                'ci/cd', 'microservices', 'cloud architecture'
            ],
            'cybersecurity': [
                'penetration testing', 'security', 'cryptography', 'network security',
                'ethical hacking', 'vulnerability assessment', 'firewall'
            ]
        }
    
    def extract_skills(self, text: str) -> Dict[str, List[str]]:
        doc = self.nlp(text.lower())
        found_skills = defaultdict(list)
        
        # Extract skills using NER and pattern matching
        for domain, skills in self.domain_skills.items():
            for skill in skills:
                if skill in text.lower():
                    found_skills[domain].append(skill)
        
        # Extract years of experience per domain
        experience_patterns = {
            domain: re.compile(f"(\d+)[\s-]*(?:year|yr)s?.*?(?:experience|exp)?.*?{domain}", re.I)
            for domain in self.domain_skills.keys()
        }
        
        for domain, pattern in experience_patterns.items():
            matches = pattern.findall(text)
            if matches:
                found_skills[f"{domain}_experience"] = max(map(int, matches))
        
        return dict(found_skills) 