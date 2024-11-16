class ResumeAnalysisError(Exception):
    """Base exception for resume analysis errors"""
    pass

class LLMError(ResumeAnalysisError):
    """Raised when LLM processing fails"""
    pass

class TokenError(ResumeAnalysisError):
    """Raised for token-related issues"""
    pass

class RateLimitError(ResumeAnalysisError):
    """Raised when rate limit is exceeded"""
    pass 