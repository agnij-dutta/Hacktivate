from typing import Dict, List, Optional
import json
import asyncio
from utils.cache import Cache
from utils.exceptions import LLMError
from config import Config
import re
from openai import OpenAI

class LLMAnalyzer:
    def __init__(self, config: Optional[Config] = None):
        """Initialize LLM Analyzer with optional configuration"""
        self.config = config or Config()
        self.cache = Cache(ttl=self.config.CACHE_TTL)
        self.client = OpenAI(api_key=self.config.OPENAI_API_KEY)
        
    async def analyze_resume(self, resume_text: str) -> Dict:
        """
        Perform deep analysis of resume using LLM with caching
        
        Args:
            resume_text: The resume text to analyze
            
        Returns:
            Dict containing structured analysis
            
        Raises:
            LLMError: If analysis fails
        """
        cache_key = f"resume_analysis_{hash(resume_text)}"
        
        # Check cache
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result
            
        try:
            prompts = self._generate_analysis_prompts(resume_text)
            analyses = {}
            
            # Process prompts concurrently
            tasks = [
                self._get_llm_response(prompt) 
                for aspect, prompt in prompts.items()
            ]
            results = await asyncio.gather(*tasks)
            
            for (aspect, _), result in zip(prompts.items(), results):
                analyses[aspect] = result
                
            structured_analysis = self._structure_analysis(analyses)
            self.cache.set(cache_key, structured_analysis)
            
            return structured_analysis
            
        except Exception as e:
            raise LLMError(f"Resume analysis failed: {str(e)}")

    def _generate_analysis_prompts(self, resume_text: str) -> Dict[str, str]:
        """Generate structured prompts for different aspects of analysis"""
        base_prompt = (
            "You are an expert resume analyzer. Analyze the following resume "
            "section and provide a detailed response in valid JSON format. "
            "Be specific and thorough in your analysis."
        )
        
        return {
            'technical_depth': f"""{base_prompt}
            Task: Analyze the technical depth and expertise shown in this resume.
            Focus areas:
            - Technical skill complexity
            - Project sophistication
            - Technical achievements
            
            Resume: {resume_text}
            
            Required JSON format:
            {{
                "skill_depth_score": <score 1-10>,
                "key_technical_achievements": [<list of achievements>],
                "areas_of_expertise": [<list of areas>],
                "skill_breakdown": {{
                    "advanced": [<skills>],
                    "intermediate": [<skills>],
                    "basic": [<skills>]
                }}
            }}""",
            
            'soft_skills': f"""{base_prompt}
            Task: Evaluate soft skills and leadership potential.
            Focus areas:
            - Leadership capabilities
            - Communication skills
            - Team collaboration
            - Problem-solving approach
            
            Resume: {resume_text}
            
            Required JSON format:
            {{
                "leadership_score": <score 1-10>,
                "key_soft_skills": [<list of skills>],
                "notable_achievements": [<list of achievements>],
                "leadership_indicators": [<list of indicators>]
            }}""",
            
            'project_analysis': f"""{base_prompt}
            Task: Analyze projects and their impact.
            Focus areas:
            - Project complexity
            - Innovation level
            - Impact and results
            - Technical challenges solved
            
            Resume: {resume_text}
            
            Required JSON format:
            {{
                "project_score": <score 1-10>,
                "notable_projects": [{{
                    "name": <project name>,
                    "complexity": <score 1-10>,
                    "impact": <description>,
                    "technologies": [<list of technologies>]
                }}],
                "technical_complexity": <score 1-10>
            }}""",
            
            'growth_potential': f"""{base_prompt}
            Task: Assess growth potential and learning ability.
            Focus areas:
            - Learning agility
            - Adaptation to new technologies
            - Professional development
            - Future potential
            
            Resume: {resume_text}
            
            Required JSON format:
            {{
                "growth_score": <score 1-10>,
                "learning_indicators": [<list of indicators>],
                "improvement_areas": [<list of areas>],
                "potential_roles": [<list of future roles>]
            }}"""
        }

    async def _get_llm_response(self, prompt: str) -> Dict:
        """Get response from OpenAI with error handling and retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are an expert resume analyzer. Provide responses in valid JSON format."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=1000
                )
                
                response_text = response.choices[0].message.content
                
                # Try to extract JSON from response
                try:
                    return json.loads(response_text)
                except json.JSONDecodeError:
                    extracted = self._extract_structured_data(response_text)
                    if extracted:
                        return extracted
                    
                    if attempt == max_retries - 1:
                        raise LLMError("Failed to parse LLM response as JSON")
                        
            except Exception as e:
                if attempt == max_retries - 1:
                    raise LLMError(f"LLM processing failed: {str(e)}")
                await asyncio.sleep(1)  # Wait before retry

    def _extract_structured_data(self, text: str) -> Optional[Dict]:
        """Extract structured data from unstructured LLM response using regex"""
        try:
            # Look for JSON-like structures
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            # Fallback: Extract key-value pairs
            score_pattern = r'(?:score|rating):\s*(\d+)'
            scores = re.findall(score_pattern, text, re.I)
            
            list_pattern = r'(?:skills|achievements|areas):\s*\[(.*?)\]'
            lists = re.findall(list_pattern, text, re.I)
            
            return {
                'extracted_score': int(scores[0]) if scores else 5,
                'extracted_items': [
                    item.strip() 
                    for sublist in lists 
                    for item in sublist.split(',')
                ] if lists else []
            }
            
        except Exception:
            return None

    def _structure_analysis(self, analyses: Dict) -> Dict:
        """Structure the analysis results with validation"""
        try:
            structured = {
                'technical_analysis': analyses['technical_depth'],
                'soft_skills_analysis': analyses['soft_skills'],
                'project_evaluation': analyses['project_analysis'],
                'growth_assessment': analyses['growth_potential'],
                'overall_llm_score': self._calculate_overall_score(analyses)
            }
            
            # Validate scores
            self._validate_scores(structured)
            return structured
            
        except Exception as e:
            raise LLMError(f"Failed to structure analysis: {str(e)}")

    def _validate_scores(self, analysis: Dict) -> None:
        """Validate all scores are within expected range"""
        for category, data in analysis.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if 'score' in key.lower() and (
                        not isinstance(value, (int, float)) or 
                        not 0 <= value <= 10
                    ):
                        raise ValueError(
                            f"Invalid score in {category}.{key}: {value}"
                        )

    def _calculate_overall_score(self, analyses: Dict) -> float:
        """Calculate weighted overall score"""
        weights = {
            'technical_depth': 0.4,
            'soft_skills': 0.2,
            'project_analysis': 0.25,
            'growth_potential': 0.15
        }
        
        weighted_scores = []
        for aspect, weight in weights.items():
            score = analyses[aspect].get(
                next(
                    k for k in analyses[aspect].keys() 
                    if 'score' in k.lower()
                ), 
                0
            )
            weighted_scores.append(score * weight)
            
        return round(sum(weighted_scores), 2)