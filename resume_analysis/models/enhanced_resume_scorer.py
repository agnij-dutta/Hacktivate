from typing import Dict, Optional
from .llm_analyzer import LLMAnalyzer
from .resume_scorer import ResumeScorer
from config import Config
from utils.exceptions import ResumeAnalysisError
from parsers.profile_parser import ProfileParser
import re

class EnhancedResumeScorer:
    def __init__(self, config: Config):
        self.config = config
        self.llm_analyzer = LLMAnalyzer(config)
        self.traditional_scorer = ResumeScorer(config.GITHUB_TOKEN)
        self.profile_parser = ProfileParser({
            'github_token': config.GITHUB_TOKEN,
            'linkedin_token': config.LINKEDIN_TOKEN
        })
    
    async def analyze_profile(
        self,
        resume_pdf: bytes,
        github_username: Optional[str] = None,
        linkedin_url: Optional[str] = None
    ) -> Dict:
        try:
            # Parse all sources into concatenated text
            concatenated_text = await self.profile_parser.parse_all_sources(
                resume_pdf,
                github_username,
                linkedin_url
            )
            
            # Extract section-specific content for targeted analysis
            sections = self._split_sections(concatenated_text)
            
            # Perform analyses
            traditional_analysis = await self.traditional_scorer.analyze_async(
                sections['resume']  # Use primarily resume section for traditional analysis
            )
            
            # Use full concatenated text for LLM analysis
            llm_analysis = await self.llm_analyzer.analyze_resume(concatenated_text)
            
            # Combine analyses with section awareness
            return self._combine_analyses(
                traditional_analysis, 
                llm_analysis,
                sections
            )
            
        except Exception as e:
            raise ResumeAnalysisError(f"Analysis failed: {str(e)}")
    
    def _split_sections(self, concatenated_text: str) -> Dict[str, str]:
        """Split concatenated text into its component sections"""
        sections = {
            'resume': '',
            'github': '',
            'linkedin': ''
        }
        
        # Split text on section markers
        parts = re.split(r'\n===\n', concatenated_text)
        for part in parts:
            if 'RESUME SECTION:' in part:
                sections['resume'] = part.split('RESUME SECTION:')[1].strip()
            elif 'GITHUB SECTION:' in part:
                sections['github'] = part.split('GITHUB SECTION:')[1].strip()
            elif 'LINKEDIN SECTION:' in part:
                sections['linkedin'] = part.split('LINKEDIN SECTION:')[1].strip()
                
        return sections
    
    def _combine_analyses(self, 
                         traditional: Dict, 
                         llm: Dict,
                         sections: Dict[str, str]) -> Dict:
        enhanced_scores = {}
        
        for domain in traditional['domain_scores']:
            # Calculate section-specific scores
            github_factor = 1.0 if sections['github'] else 0.8
            linkedin_factor = 1.0 if sections['linkedin'] else 0.9
            
            # Combine traditional and LLM scores with weighted average
            traditional_score = traditional['domain_scores'][domain]
            llm_technical_score = llm['technical_analysis']['skill_depth_score']
            llm_project_score = llm['project_evaluation']['project_score']
            
            # Apply source availability factors
            enhanced_scores[domain] = {
                'score': round(
                    0.4 * traditional_score * github_factor * linkedin_factor +
                    0.3 * llm_technical_score +
                    0.3 * llm_project_score,
                    2
                ),
                'technical_depth': llm['technical_analysis'],
                'project_insights': llm['project_evaluation'],
                'growth_potential': llm['growth_assessment'],
                'source_completeness': {
                    'resume': bool(sections['resume']),
                    'github': bool(sections['github']),
                    'linkedin': bool(sections['linkedin'])
                }
            }
        
        return enhanced_scores
    
    def _generate_recommendations(self, enhanced_scores: Dict) -> Dict:
        recommendations = {
            'strongest_domains': [],
            'improvement_areas': [],
            'recommended_focus': [],
            'learning_path': []
        }
        
        # Analyze scores and generate specific recommendations
        for domain, details in enhanced_scores.items():
            if details['score'] >= 8.0:
                recommendations['strongest_domains'].append(domain)
            elif details['score'] < 6.0:
                recommendations['improvement_areas'].append(domain)
                
            # Add learning recommendations based on growth potential
            if details['growth_potential']['growth_score'] >= 7.0:
                recommendations['learning_path'].append({
                    'domain': domain,
                    'focus_areas': details['growth_potential']['improvement_areas']
                })
        
        return recommendations 