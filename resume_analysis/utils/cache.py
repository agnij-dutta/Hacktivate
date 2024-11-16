from typing import Any, Optional
from datetime import datetime, timedelta

class Cache:
    def __init__(self, ttl: int = 3600):
        self._cache = {}
        self._ttl = ttl
    
    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            item = self._cache[key]
            if datetime.now() < item['expires']:
                return item['value']
            del self._cache[key]
        return None
    
    def set(self, key: str, value: Any):
        self._cache[key] = {
            'value': value,
            'expires': datetime.now() + timedelta(seconds=self._ttl)
        } 