import asyncio
from typing import Optional
from datetime import datetime, timedelta

# Cache configuration
import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Optional

CACHE_TTL = timedelta(days=1)
MAX_CACHE_SIZE = 1000
CACHE_DIR = 'cache_files'

class AnalysisCache:
    def __init__(self):
        self.cache_dir = CACHE_DIR
        os.makedirs(self.cache_dir, exist_ok=True)
        self.lock = asyncio.Lock()

    def _get_cache_path(self, key: str) -> str:
        # Sanitize key to create a valid filename
        safe_key = key.replace('/', '_').replace('\\', '_')
        return os.path.join(self.cache_dir, f"{safe_key}.json")

    async def get(self, key: str) -> Optional[dict]:
        async with self.lock:
            path = self._get_cache_path(key)
            if not os.path.exists(path):
                return None
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                timestamp = datetime.fromisoformat(data.get('timestamp'))
                if datetime.now() - timestamp < CACHE_TTL:
                    return data.get('value')
                else:
                    os.remove(path)
            except Exception as e:
                # Handle exceptions such as JSON decoding errors
                print(f"Error reading cache file {path}: {e}")
            return None

    async def set(self, key: str, value: dict):
        async with self.lock:
            path = self._get_cache_path(key)
            data = {
                'timestamp': datetime.now().isoformat(),
                'value': value
            }
            try:
                with open(path, 'w') as f:
                    json.dump(data, f)
                # Implement cache size limit
                files = sorted(
                    ((os.path.getmtime(f), f) for f in os.listdir(self.cache_dir)),
                    key=lambda x: x[0]
                )
                if len(files) > MAX_CACHE_SIZE:
                    for _, f in files[:len(files) - MAX_CACHE_SIZE]:
                        os.remove(os.path.join(self.cache_dir, f))
            except Exception as e:
                # Handle exceptions such as file write errors
                print(f"Error writing cache file {path}: {e}")


analysis_cache = AnalysisCache()