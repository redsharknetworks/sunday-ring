import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
OTX_API_KEY = os.getenv("OTX_API_KEY")
MAXMIND_DB = os.getenv("MAXMIND_DB")
