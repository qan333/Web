# app/routes/detect_blacklist_router.py
"""
Detection router (extended with blacklist checks)

Không sửa code cũ trong detect_router, chỉ cung cấp endpoint mới:
- POST /detect-bl/account
- POST /detect-bl/transaction
"""
import logging
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.services.detection_service import DetectionService
from app.services.blacklist_lookup import check_address_with_blacklists
from app.services.etherscan_client import (
    get_transaction_by_hash,
    get_transaction_receipt,
    decode_function_name,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/detect-bl", tags=["detect-blacklist"])

_detection_service: Optional[DetectionService] = None


def get_detection_service() -> DetectionService:
    """Lazy init DetectionService (không ảnh hưởng detect_router cũ)."""
    global _detection_service
    if _detection_service is None:
        logger.info("[detect-bl] Initializing DetectionService...")
        _detection_service = DetectionService()
        logger.info("[detect-bl] DetectionService initialized")
    return _detection_service


# ====== Pydantic models (copy nhẹ từ detect_router) ======

class DetectAccountIn(BaseModel):
    account_address: str = Field(..., description="Ethereum address to analyze")
    explain: bool = Field(
        False, description="Include SHAP explanations from the AI model"
    )
    explain_with_llm: bool = Field(
        False, description="Include LLM explanations (requires explain=True)"
    )
    max_transactions: int = Field(
        1000, description="Maximum number of transactions to fetch"
    )


class DetectTransactionIn(BaseModel):
    transaction_hash: Optional[str] = Field(
        None,
        description="Transaction hash for manual analysis (will fetch from Etherscan)",
    )

    # pending tx
    from_address: Optional[str] = Field(
        None, description="From address (for pending transaction)"
    )
    to_address: Optional[str] = Field(
        None, description="To address (for pending transaction)"
    )
    value: Optional[str] = Field(
        None, description="Transaction value in wei (for pending transaction)"
    )
    gasPrice: Optional[str] = Field(
        None, description="Gas price (for pending transaction)"
    )
    gasUsed: Optional[str] = Field(
        None, description="Gas used (for pending transaction)"
    )
    timestamp: Optional[int] = Field(
        None, description="Transaction timestamp (for pending transaction)"
    )
    function_call: Optional[List[str]] = Field(
        None, description="Function calls in transaction (for pending transaction)"
    )
    input: Optional[str] = Field(
        None, description="Input data (for pending transaction)"
    )
    contract_address: Optional[str] = Field(
        None, description="Contract address (if NFT transfer)"
    )
    token_value: Optional[str] = Field(None, description="Token/NFT value")

    explain: bool = Field(True, description="Include SHAP explanations")
    explain_with_llm: bool = Field(True, description="Include LLM explanations")


def _parse_int(value: Optional[str]) -> int:
    if not value or value == "0":
        return 0
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except Exception:
        return 0


async def _fetch_tx_from_etherscan(tx_hash: str) -> Dict[str, Any]:
    tx_data = await get_transaction_by_hash(tx_hash)
    tx_receipt = await get_transaction_receipt(tx_hash)

    if not tx_data:
        raise HTTPException(
            status_code=404, detail=f"Transaction {tx_hash} not found on Etherscan"
        )

    from_address = (tx_data.get("from") or "").lower()
    to_address = (tx_data.get("to") or "").lower()
    value = _parse_int(tx_data.get("value", "0"))
    gas_price = _parse_int(tx_data.get("gasPrice", "0"))
    gas_used = _parse_int(tx_receipt.get("gasUsed", "0"))
    block_number = _parse_int(tx_data.get("blockNumber", "0"))
    input_data = tx_data.get("input", "0x")

    function_calls = decode_function_name(input_data)
    timestamp = int(time.time())

    contract_address = to_address
    is_nft_tx = input_data and input_data != "0x" and len(input_data) > 10

    return {
        "from_address": from_address,
        "to_address": to_address,
        "value": value,
        "gasPrice": gas_price,
        "gasUsed": gas_used,
        "timestamp": timestamp,
        "function_call": function_calls,
        "transaction_hash": tx_hash,
        "blockNumber": block_number,
        "contract_address": contract_address,
        "token_value": 0,
        "nft_floor_price": 0,
        "nft_average_price": 0,
        "nft_total_volume": 0,
        "nft_total_sales": 0,
        "nft_num_owners": 0,
        "nft_market_cap": 0,
        "nft_7day_volume": 0,
        "nft_7day_sales": 0,
        "nft_7day_avg_price": 0,
        "tx_type": "erc721" if is_nft_tx else "normal",
    }

# ================== ACCOUNT WITH BLACKLIST ==================
@router.post("/account")
async def detect_account_with_blacklist(body: DetectAccountIn):
    # validate explain flags (giữ lại cho đồng bộ, dù route này không dùng model)
    if body.explain_with_llm and not body.explain:
        raise HTTPException(
            status_code=400,
            detail="explain must be True when explain_with_llm is True",
        )

    addr = (body.account_address or "").strip().lower()
    logger.info(f"[detect-bl] Account request: {addr}")

    # B1 + B2: check blacklist + etherscan đúng flow bạn muốn
    bl = check_address_with_blacklists(addr)
    logger.info(
        f"[detect-bl] check_address: "
        f"local={bl['in_local_blacklist']}, "
        f"etherscan_exists={bl['etherscan_exists']}, "
        f"etherscan_tagged={bl['etherscan_tagged']}, "
        f"is_scam={bl['is_scam']}, source={bl['source']}"
    )

    # 1) Nếu trong blacklist local -> scam 100%
    # 2) Nếu không, nhưng etherscan tagged -> scam 100%
    if bl["is_scam"]:
        detection_mode = (
            "blacklist_local" if bl["source"] == "local" else "blacklist_etherscan"
        )
        return {
            "account_address": addr,
            "detection_mode": detection_mode,
            "account_scam_probability": 1.0,
            "risk_level": "high",
            "blacklist": bl,
            "model_used": None,
            "explanations": {
                "account": {
                    "reason": (
                        "Address is marked as phishing by local blacklist"
                        if bl["source"] == "local"
                        else "Address is tagged as phishing/scam on Etherscan"
                    ),
                    "blacklist": bl,
                }
            },
        }

    # 3) Nếu Etherscan báo không tồn tại -> trả lỗi cho UI
    if not bl["etherscan_exists"]:
        raise HTTPException(
            status_code=404,
            detail="Address not found on Etherscan and not present in blacklist",
        )

    # 4) Tồn tại & không tagged -> KHÔNG CHẠY MODEL,
    #    chỉ trả về kết quả 'an toàn theo blacklist/etherscan'
    return {
        "account_address": addr,
        "detection_mode": "blacklist_only",
        "account_scam_probability": 0.0,
        "risk_level": "low",
        "blacklist": bl,
        "model_used": None,
        "explanations": {
            "account": {
                "reason": (
                    "Address is not in local blacklist and not tagged as "
                    "phishing/scam on Etherscan"
                ),
                "blacklist": bl,
            }
        },
    }

# ================== TRANSACTION WITH BLACKLIST ==================


@router.post("/transaction")
async def detect_transaction_with_blacklist(body: DetectTransactionIn):
    """
    Detect transaction với bước blacklist check trên from/to trước model AI.
    """
    try:
        # Chuẩn hoá transaction_data (giống detect_router)
        if body.transaction_hash:
            tx = await _fetch_tx_from_etherscan(body.transaction_hash)
        elif body.from_address and body.to_address:
            function_calls = body.function_call or []
            if not function_calls and body.input:
                function_calls = decode_function_name(body.input)

            tx = {
                "from_address": body.from_address.lower(),
                "to_address": body.to_address.lower(),
                "value": _parse_int(body.value),
                "gasPrice": _parse_int(body.gasPrice),
                "gasUsed": _parse_int(body.gasUsed),
                "timestamp": body.timestamp or int(time.time()),
                "function_call": function_calls,
                "contract_address": (
                    (body.contract_address or body.to_address) or ""
                ).lower(),
                "token_value": _parse_int(body.token_value),
                "transaction_hash": "",
                "blockNumber": 0,
                "nft_floor_price": 0,
                "nft_average_price": 0,
                "nft_total_volume": 0,
                "nft_total_sales": 0,
                "nft_num_owners": 0,
                "nft_market_cap": 0,
                "nft_7day_volume": 0,
                "nft_7day_sales": 0,
                "nft_7day_avg_price": 0,
                "tx_type": "erc721" if body.contract_address else "normal",
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Either 'transaction_hash' or "
                    "'from_address' + 'to_address' must be provided"
                ),
            )

        from_addr = tx["from_address"]
        to_addr = tx["to_address"]

        # B1: blacklist check cho from & to
        bl_from = full_blacklist_check(from_addr)
        bl_to = full_blacklist_check(to_addr)

        any_confirmed = bl_from["is_confirmed_phishing"] or bl_to[
            "is_confirmed_phishing"
        ]

        if any_confirmed:
            return {
                "transaction_hash": tx.get("transaction_hash") or body.transaction_hash,
                "detection_mode": "blacklist",
                "transaction_scam_probability": 0.99,
                "risk_level": "high",
                "blacklist": {
                    "from": bl_from,
                    "to": bl_to,
                },
                "explanations": {
                    "transaction": {
                        "reason": "Transaction involves address(es) confirmed as phishing by unified blacklist and Etherscan tags.",
                        "blacklist": {
                            "from": bl_from,
                            "to": bl_to,
                        },
                    }
                },
            }

        # B2: fallback sang model như route cũ
        detection_service = get_detection_service()
        detection_start = time.time()
        result = await detection_service.detect_transaction(
            transaction_data=tx,
            explain=body.explain,
            explain_with_llm=body.explain_with_llm,
        )
        detection_time = time.time() - detection_start

        # gắn info blacklist
        result.setdefault("blacklist", {"from": bl_from, "to": bl_to})
        if "explanations" in result:
            result["explanations"].setdefault("transaction", {})
            result["explanations"]["transaction"]["blacklist"] = {
                "from": bl_from,
                "to": bl_to,
            }
        else:
            result["explanations"] = {
                "transaction": {"blacklist": {"from": bl_from, "to": bl_to}}
            }

        logger.info(
            f"[detect-bl] Tx detection completed: prob={result.get('transaction_scam_probability')}, "
            f"mode={result.get('detection_mode')}, time={detection_time:.2f}s"
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[detect-bl] Transaction detection failed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Transaction detection failed: {str(e)}"
        )
