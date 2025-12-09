from pydantic import BaseModel
import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from backend directory
# config.py is in backend/app/, so we go up 2 levels to reach backend/
BACKEND_DIR = Path(__file__).parent.parent
ENV_FILE = BACKEND_DIR / ".env"

# Load environment variables from .env file
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
    print(f"✅ Loaded environment variables from: {ENV_FILE}")
else:
    print(f"⚠️  .env file not found at: {ENV_FILE}")
    # Try to load from current directory as fallback
    load_dotenv()

class Settings(BaseModel):
    api_title: str = os.getenv("API_TITLE", "ScamRadar Backend")
    api_version: str = os.getenv("API_VERSION", "0.1.0")
    api_debug: bool = os.getenv("API_DEBUG", "false").lower() == "true"
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./scamradar.db")
    policy_etag: str = os.getenv("POLICY_ETAG", "v1")
    
    # Etherscan API Key
    etherscan_api_key: str = os.getenv("ETHERSCAN_API_KEY", "")
    etherscan_keys: list[str] = []
    etherscan_chainid: int = int(os.getenv("ETHERSCAN_CHAINID", "1"))  # 1 for Ethereum mainnet
    
    # Rarible API Key
    rarible_api_key: str = os.getenv("RARIBLE_API_KEY")
    
    # Gemini API Key
    gemini_api_key: str = os.getenv("GEMINI_API_KEY")
    
    # Model paths
    model_dir: str = os.getenv("MODEL_DIR", "models")
    features_dir: str = os.getenv("FEATURES_DIR", "features")

settings = Settings()

# Support multiple Etherscan keys
raw_keys = os.getenv("ETHERSCAN_KEYS") or settings.etherscan_api_key
if raw_keys:
    try:
        settings.etherscan_keys = json.loads(raw_keys) if raw_keys.startswith("[") else [raw_keys]
    except Exception:
        settings.etherscan_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

