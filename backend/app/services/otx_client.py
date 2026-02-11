import requests
from app.core.config import OTX_API_KEY

BASE_URL = "https://otx.alienvault.com/api/v1"

HEADERS = {
    "X-OTX-API-KEY": OTX_API_KEY
}

def fetch_indicators(indicator_type, limit=500):
    url = f"{BASE_URL}/indicators/export"
    params = {"type": indicator_type, "limit": limit}

    response = requests.get(url, headers=HEADERS, params=params, timeout=15)
    response.raise_for_status()

    return response.text.splitlines()
