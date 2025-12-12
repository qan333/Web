from pydantic import BaseModel
import os
import json
from pathlib import Path
from dotenv import load_dotenv, dotenv_values

# Load .env file from backend directory
# config.py is in backend/app/, so we go up 2 levels to reach backend/
BACKEND_DIR = Path(__file__).parent.parent
ENV_FILE = BACKEND_DIR / ".env"

# Load environment variables from .env file FIRST, before any Settings initialization
# Use override=True to ensure .env values take precedence over system env vars
if ENV_FILE.exists():
    # Load .env file and override existing environment variables
    load_dotenv(ENV_FILE, override=True)
    print(f"✅ Loaded environment variables from: {ENV_FILE.absolute()}")
    
    # Also load as dict to verify values are loaded correctly
    env_dict = dotenv_values(ENV_FILE)
    if env_dict:
        # Update os.environ to ensure all values are available
        for key, value in env_dict.items():
            if value is not None:
                os.environ.setdefault(key, value)
        print(f"✅ Loaded {len(env_dict)} environment variables from .env file")
else:
    print(f"⚠️  .env file not found at: {ENV_FILE.absolute()}")
    # Try to load from current directory as fallback
    load_dotenv(override=True)

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
    
    # Rarible API Keys (support multiple keys for load balancing)
    rarible_api_key: str = os.getenv("RARIBLE_API_KEY", "")
    rarible_api_keys: list[str] = []
    
    # Gemini API Key
    gemini_api_key: str = os.getenv("GEMINI_API_KEY","AIzaSyCXQOXRGuEBEaHBxGye2VpIl5JtDsbJbTk")
    
    # Model paths
    model_dir: str = os.getenv("MODEL_DIR", "models")
    features_dir: str = os.getenv("FEATURES_DIR", "features")

settings = Settings()

# Support multiple Etherscan keys
# Read from environment variable first (from .env file)
raw_keys = os.getenv("ETHERSCAN_KEYS", "").strip()
if not raw_keys:
    # Fallback to single key if ETHERSCAN_KEYS not set
    raw_keys = os.getenv("ETHERSCAN_API_KEY", "").strip()

if raw_keys:
    try:
        # Try parsing as JSON array first
        if raw_keys.startswith("[") and raw_keys.endswith("]"):
            settings.etherscan_keys = json.loads(raw_keys)
        else:
            # Parse as comma-separated string
            settings.etherscan_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    except Exception as e:
        print(f"⚠️  Error parsing ETHERSCAN_KEYS: {e}, using as single key")
        settings.etherscan_keys = [raw_keys]

# Log loaded keys (without exposing full keys)
if settings.etherscan_keys:
    print(f"✅ Loaded {len(settings.etherscan_keys)} Etherscan API key(s)")

# Support multiple Rarible keys
# Read from environment variable first (from .env file)
rarible_raw_keys = os.getenv("RARIBLE_API_KEYS", "").strip()
if not rarible_raw_keys:
    # Fallback to single key if RARIBLE_API_KEYS not set
    rarible_raw_keys = os.getenv("RARIBLE_API_KEY", "").strip()

if rarible_raw_keys:
    try:
        # Try parsing as JSON array first
        if rarible_raw_keys.startswith("[") and rarible_raw_keys.endswith("]"):
            settings.rarible_api_keys = json.loads(rarible_raw_keys)
        else:
            # Parse as comma-separated string
            settings.rarible_api_keys = [k.strip() for k in rarible_raw_keys.split(",") if k.strip()]
    except Exception as e:
        print(f"⚠️  Error parsing RARIBLE_API_KEYS: {e}, using as single key")
        settings.rarible_api_keys = [rarible_raw_keys]
else:
    # Fallback: use single key from settings if available
    settings.rarible_api_keys = [settings.rarible_api_key] if settings.rarible_api_key else []

# Log loaded keys (without exposing full keys)
if settings.rarible_api_keys:
    print(f"✅ Loaded {len(settings.rarible_api_keys)} Rarible API key(s)")

