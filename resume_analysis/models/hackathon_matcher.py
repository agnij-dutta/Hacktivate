from typing import Dict, List
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from .resume_scorer import ResumeScorer

class HackathonMatcher:
    def __init__(self, historical_data_path: str = None):
        self.resume_scorer = ResumeScorer()
        self.model = RandomForestClassifier()
        if historical_data_path:
            self._train_model(historical_data_path)
    
    def _train_model(self, data_path: str):
        # Load and prepare historical data
        data = pd.read_csv(data_path)
        X = data[['domain_score', 'experience', 'github_score']]
        y = data['accepted']
        self.model.fit(X, y)
    
    def match_hackathons(self, 
                         enhanced_analysis: Dict, 
                         hackathons: List[Dict]) -> List[Dict]:
        matches = []
        
        for hackathon in hackathons:
            # Get domain-specific scores
            domain_score = enhanced_analysis['enhanced_scores'].get(
                hackathon['primary_track'], 
                {}
            ).get('score', 0)
            
            # Get LLM insights
            technical_depth = enhanced_analysis['llm_analysis']['technical_analysis']
            project_evaluation = enhanced_analysis['llm_analysis']['project_evaluation']
            
            # Calculate enhanced compatibility score
            compatibility = self._calculate_enhanced_compatibility(
                domain_score,
                technical_depth,
                project_evaluation,
                hackathon
            )
            
            matches.append({
                'hackathon': hackathon,
                'compatibility_score': round(compatibility, 2),
                'technical_match': {
                    'score': technical_depth['skill_depth_score'],
                    'strengths': technical_depth['key_technical_achievements']
                },
                'project_match': {
                    'score': project_evaluation['project_score'],
                    'complexity_match': project_evaluation['technical_complexity']
                },
                'recommendations': self._generate_track_recommendations(
                    enhanced_analysis,
                    hackathon
                )
            })
        
        return sorted(matches, key=lambda x: x['compatibility_score'], reverse=True)
    
    def _calculate_enhanced_compatibility(self,
                                        domain_score: float,
                                        technical_depth: Dict,
                                        project_evaluation: Dict,
                                        hackathon: Dict) -> float:
        # Weight different factors for final compatibility score
        weights = {
            'domain_score': 0.3,
            'technical_depth': 0.3,
            'project_complexity': 0.2,
            'difficulty_match': 0.2
        }
        
        difficulty_factor = self._calculate_difficulty_match(
            technical_depth['skill_depth_score'],
            hackathon['difficulty']
        )
        
        return (
            weights['domain_score'] * domain_score +
            weights['technical_depth'] * technical_depth['skill_depth_score'] +
            weights['project_complexity'] * project_evaluation['project_score'] +
            weights['difficulty_match'] * difficulty_factor
        )
    
    def _calculate_difficulty_match(self, technical_depth_score: float, hackathon_difficulty: str) -> float:
        # Calculate difficulty match factor
        difficulty_factor = {
            'Beginner': 1.2,
            'Intermediate': 1.0,
            'Advanced': 0.8
        }.get(hackathon_difficulty, 1.0)
        
        return min(technical_depth_score / 10 * difficulty_factor, 1.0)
    
    def _generate_track_recommendations(self, 
                                        enhanced_analysis: Dict, 
                                        hackathon: Dict) -> List[str]:
        # Generate track recommendations based on enhanced analysis
        domain_scores = enhanced_analysis['enhanced_scores']
        return [
            track for track in hackathon['tracks']
            if domain_scores.get(track, {}).get('score', 0) >= 6.0  # Recommend if score is 6+ out of 10
        ] 