# app/services/blacklist_lookup.py
import os
import re
import time
import csv
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

import requests

ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

def _default_blacklist_path() -> Path:
    env = os.getenv("PHISHING_BLACKLIST_CSV")
    if env:
        return Path(env).expanduser().resolve()

    project_root = Path(__file__).resolve().parents[2]
    return project_root / "phishing_addresses" / "phishing_addresses_aggregated.csv"

BLACKLIST_CSV = _default_blacklist_path()

# ------------ LOOKUP 2: local blacklist ------------

@lru_cache()
def _load_blacklist() -> Dict[str, Dict]:
    result: Dict[str, Dict] = {}
    if not BLACKLIST_CSV.exists():
        print(f"[blacklist_lookup] WARNING: blacklist file not found: {BLACKLIST_CSV}")
        return result

    with BLACKLIST_CSV.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = (row.get("address") or "").strip().lower()
            if not ADDRESS_RE.fullmatch(addr):
                continue
            result[addr] = {
                "sources": row.get("sources", ""),
                "source_count": int(row.get("source_count", "1") or 1),
                "label": int(row.get("label", "1") or 1),
            }

    print(f"[blacklist_lookup] loaded {len(result)} local blacklist addresses")
    return result


def lookup_local_blacklist(address: str) -> Optional[Dict]:
    if not address:
        return None
    addr = address.strip().lower()
    if not ADDRESS_RE.fullmatch(addr):
        return None
    bl = _load_blacklist()
    return bl.get(addr)


# ------------ LOOKUP 1: Etherscan status + tag ------------

_SESSION = requests.Session()
_SESSION.headers.update(
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        )
    }
)

_PHISH_PATTERNS = [
    r"Phish\s*/\s*Hack",
    r"Fake_Phishing\d+",
    r"CryptoScamDB",
    r"phish.*hack",
    r"hack.*phish",
    r"scam.*phish",
    r"fraud.*phish",
]
_COMPILED_PHISH = [re.compile(p, re.IGNORECASE) for p in _PHISH_PATTERNS]

# pattern cho trang "không tìm thấy address" của Etherscan
_NOT_FOUND_PATTERNS = [
    r"Sorry, We are unable to locate the address",
    r"Unable to locate the address",
    r"Invalid Address",
    r"Address not exists",
]
_COMPILED_NOT_FOUND = [re.compile(p, re.IGNORECASE) for p in _NOT_FOUND_PATTERNS]

_ETHERSCAN_CACHE: Dict[str, Dict] = {}  # addr -> {"exists": bool, "tagged": bool}


def _parse_etherscan_html(html: str) -> Dict[str, bool]:
    # Không tồn tại
    if any(p.search(html) for p in _COMPILED_NOT_FOUND):
        return {"exists": False, "tagged": False}

    # Mặc định: tồn tại
    tagged = any(p.search(html) for p in _COMPILED_PHISH)
    return {"exists": True, "tagged": tagged}


def lookup_etherscan_status(address: str, timeout: int = 10) -> Dict[str, bool]:
    """
    Trả về:
    {
      "exists": bool,   # địa chỉ có tồn tại trên Etherscan không
      "tagged": bool,   # có tag Phish/Hack/Fake_Phishing/... hay không
    }
    """
    if not address:
        return {"exists": False, "tagged": False}

    addr = address.strip().lower()
    if not ADDRESS_RE.fullmatch(addr):
        return {"exists": False, "tagged": False}

    if addr in _ETHERSCAN_CACHE:
        return _ETHERSCAN_CACHE[addr]

    url = f"https://etherscan.io/address/{addr}"
    try:
        resp = _SESSION.get(url, timeout=timeout)
    except Exception as e:
        print(f"[blacklist_lookup] Etherscan error for {addr}: {e}")
        _ETHERSCAN_CACHE[addr] = {"exists": False, "tagged": False}
        return _ETHERSCAN_CACHE[addr]

    if resp.status_code == 404:
        status = {"exists": False, "tagged": False}
    else:
        status = _parse_etherscan_html(resp.text)

    _ETHERSCAN_CACHE[addr] = status
    # nhẹ nhàng hạn chế spam
    time.sleep(1.0)
    return status


# ------------ Hàm gộp theo flow bạn yêu cầu ------------

def check_address_with_blacklists(address: str) -> Dict:
    """
    Flow:
      1) Check local blacklist.
         - Nếu có -> scam = True, exists = True, source = 'local'
      2) Nếu không có -> check Etherscan.
         - Nếu không tồn tại -> exists = False, scam = False
         - Nếu tồn tại & tagged -> scam = True, source = 'etherscan'
         - Nếu tồn tại & không tagged -> scam = False

    Trả về:
      {
        "address": str,
        "in_local_blacklist": bool,
        "local_info": dict|None,
        "etherscan_exists": bool,
        "etherscan_tagged": bool,
        "is_scam": bool,
        "source": "local" | "etherscan" | "model" | "none"
      }
    """
    addr = (address or "").strip().lower()

    local_info = lookup_local_blacklist(addr)
    if local_info:
        return {
            "address": addr,
            "in_local_blacklist": True,
            "local_info": local_info,
            "etherscan_exists": True,   # mình coi như tồn tại luôn
            "etherscan_tagged": True,   # để biểu diễn “chắc chắn xấu”
            "is_scam": True,
            "source": "local",
        }

    # Không nằm trong local -> qua Etherscan
    es = lookup_etherscan_status(addr)
    if not es["exists"]:
        return {
            "address": addr,
            "in_local_blacklist": False,
            "local_info": None,
            "etherscan_exists": False,
            "etherscan_tagged": False,
            "is_scam": False,
            "source": "none",
        }

    if es["tagged"]:
        return {
            "address": addr,
            "in_local_blacklist": False,
            "local_info": None,
            "etherscan_exists": True,
            "etherscan_tagged": True,
            "is_scam": True,
            "source": "etherscan",
        }

    # tồn tại nhưng không tagged -> để model quyết định
    return {
        "address": addr,
        "in_local_blacklist": False,
        "local_info": None,
        "etherscan_exists": True,
        "etherscan_tagged": False,
        "is_scam": False,
        "source": "none",
    }
