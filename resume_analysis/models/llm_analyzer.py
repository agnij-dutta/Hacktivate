from typing import Dict, List, Optional
import json
import asyncio
from utils.cache import Cache
from utils.exceptions import LLMError
from config import Config
import requests
import re

class LLMAnalyzer:
    def __init__(self, config: Optional[Config] = None):
        """Initialize LLM Analyzer with optional configuration"""
        self.config = config or Config()
        self.cache = Cache(ttl=self.config.CACHE_TTL)
        self.api_url = "https://api-inference.huggingface.co/models/facebook/opt-350m"
        self.headers = {"Authorization": f"Bearer {self.config.HUGGINGFACE_TOKEN}"}
        
    async def analyze_resume(self, resume_text: str) -> Dict:
        """Analyze resume using LLM"""
        cache_key = f"resume_analysis_{hash(resume_text)}"
        
        cached_result = self.cache.get(cache_key)
        if cached_result:
            return cached_result
            
        try:
            prompts = self._generate_analysis_prompts(resume_text)
            analyses = {}
            
            for aspect, prompt in prompts.items():
                result = await self._get_llm_response(prompt)
                analyses[aspect] = result
                
            structured_analysis = self._structure_analysis(analyses)
            self.cache.set(cache_key, structured_analysis)
            
            return structured_analysis
            
        except Exception as e:
            raise LLMError(f"Resume analysis failed: {str(e)}")

    async def _get_llm_response(self, prompt: str) -> Dict:
        """Get response from Hugging Face Inference API"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers=self.headers,
                    json={"inputs": prompt, "parameters": {"max_length": 500}}
                )
                
                if response.status_code == 200:
                    response_text = response.json()[0]["generated_text"]
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError:
                        extracted = self._extract_structured_data(response_text)
                        if extracted:
                            return extracted
                        
                if attempt == max_retries - 1:
                    raise LLMError(f"Failed to get valid response: {response.text}")
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    raise LLMError(f"LLM processing failed: {str(e)}")
                await asyncio.sleep(1)
                
        return {}  # Fallback empty response

    def _extract_structured_data(self, text: str) -> Optional[Dict]:
        """Extract structured data from unstructured LLM response"""
        try:
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            # Fallback extraction
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

    def _generate_analysis_prompts(self, resume_text: str) -> Dict[str, str]:
        """Generate analysis prompts"""
        base_prompt = (
            "Analyze this resume section and provide a JSON response. "
            "Focus on specific details and quantifiable metrics."
        )
        
        return {
            'technical_depth': f"{base_prompt} Analyze technical skills and expertise:\n{resume_text}",
            'soft_skills': f"{base_prompt} Analyze soft skills and leadership:\n{resume_text}",
            'project_analysis': f"{base_prompt} Analyze projects and impact:\n{resume_text}",
            'growth_potential': f"{base_prompt} Analyze growth potential:\n{resume_text}"
        }

    def _structure_analysis(self, analyses: Dict) -> Dict:
        """Structure the analysis results"""
        try:
            return {
                'technical_analysis': analyses.get('technical_depth', {}),
                'soft_skills_analysis': analyses.get('soft_skills', {}),
                'project_evaluation': analyses.get('project_analysis', {}),
                'growth_assessment': analyses.get('growth_potential', {}),
                'overall_score': self._calculate_overall_score(analyses)
            }
        except Exception as e:
            raise LLMError(f"Failed to structure analysis: {str(e)}")

    def _calculate_overall_score(self, analyses: Dict) -> float:
        """Calculate overall score"""
        try:
            scores = []
            for category, data in analyses.items():
                if isinstance(data, dict) and 'score' in data:
                    scores.append(data['score'])
            
            if not scores:
                return 0
            
            return round(sum(scores) / len(scores), 2)
        except Exception as e:
            raise LLMError(f"Failed to calculate overall score: {str(e)}")