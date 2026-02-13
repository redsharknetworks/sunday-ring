import os
import requests
from dotenv import load_dotenv

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE = "https://otx.alienvault.com/api/v1"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

def fetch_indicators(indicator_type, limit=500):
    url = f"{OTX_BASE}/indicators/export"
    params = {"type": indicator_type, "limit": limit}
    r = requests.get(url, headers=HEADERS, params=params, timeout=10)
    r.raise_for_status()
    return r.text.splitlines()
