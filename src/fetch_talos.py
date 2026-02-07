import requests, time, os
from db import insert_ioc

TALOS_FEED = os.getenv('TALOS_FEED_URL')  # or use API endpoint & key

def fetch_from_talos():
    # Replace with official API or feed parsing
    r = requests.get(TALOS_FEED, timeout=30)
    r.raise_for_status()
    # Example parsing if feed CSV or JSON; adapt to format
    for item in parse_feed(r.text):
        insert_ioc(item)

def parse_feed(text):
    # implement actual parsing depending on Talos feed format
    # yield dicts: {'indicator':'1.2.3.4','type':'ip','seen_at':..., 'raw': {...}}
    return []
