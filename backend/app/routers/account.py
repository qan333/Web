from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from app.services.etherscan_client import etherscan_get
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/account", tags=["account"])

# ---- các selector của hàm approval / allowance phổ biến ----
APPROVAL_SELECTORS = {
    "0x095ea7b3": "approve",             # ERC20 approve(address,uint256)
    "0xa22cb465": "setApprovalForAll",   # ERC721 / ERC1155 setApprovalForAll(address,bool)
    "0x39509351": "increaseAllowance",   # increaseAllowance(address,uint256)
    "0xa457c2d7": "decreaseAllowance",   # decreaseAllowance(address,uint256)
}

def _decode_address_from_slot(slot_hex: str) -> str:
    """
    slot_hex: 64 hex chars (32 bytes), địa chỉ nằm ở 20 bytes cuối.
    """
    slot_hex = (slot_hex or "").rjust(64, "0")[-64:]
    return "0x" + slot_hex[-40:]

def _safe_int(hex_str: str) -> int:
    try:
        return int(hex_str or "0", 16)
    except Exception:
        return 0

@router.get("/{address}/transactions")
async def get_account_transactions(
    address: str,
    limit: int = 50,
    page: int = 1,
):
    """
    Trả về danh sách transaction của 1 address từ Etherscan (đã normalize).
    """
    res = await etherscan_get(
        module="account",
        action="txlist",
        address=address,
        startblock=0,
        endblock=99999999,
        page=page,
        offset=limit,
        sort="desc",
    )

    message = (res.get("message") or "").lower()

    if "no transactions found" in message:
        return {"address": address, "transactions": []}

    if res.get("status") not in ("1", 1, "ok"):
        raise HTTPException(status_code=502, detail=res.get("message", "Etherscan error"))

    raw_txs = res["result"]

    normalized = []
    addr_lower = address.lower()
    for tx in raw_txs:
        value_wei = int(tx["value"])
        value_eth = value_wei / 10**18
        direction = "out" if tx["from"].lower() == addr_lower else "in"

        normalized.append(
            {
                "hash": tx["hash"],
                "timestamp": int(tx["timeStamp"]),
                "from": tx["from"],
                "to": tx["to"],
                "value_eth": value_eth,
                "direction": direction,
                # "risk_score": ... nếu sau này có model.
            }
        )

    return {"address": address, "transactions": normalized}


# ================== NEW: Approval audit route ==================

@router.get("/{address}/approvals")
async def get_account_approvals(
    address: str,
    limit: int = 200,   # có thể tăng lên tùy ý
    page: int = 1,
):
    """
    Liệt kê các giao dịch Approval / setApprovalForAll có liên quan tới address.

    - Dùng txlist Etherscan
    - Lọc theo function selector (approve, setApprovalForAll, increase/decreaseAllowance)
    - Decode spender + allowance
    - Gắn thêm risk_score / risk_level heuristic đơn giản
    """
    res = await etherscan_get(
        module="account",
        action="txlist",
        address=address,
        startblock=0,
        endblock=99999999,
        page=page,
        offset=limit,
        sort="desc",
    )

    message = (res.get("message") or "").lower()

    if "no transactions found" in message:
        return {"address": address, "approvals": []}

    if res.get("status") not in ("1", 1, "ok"):
        raise HTTPException(status_code=502, detail=res.get("message", "Etherscan error"))

    raw_txs = res["result"]
    addr_lower = address.lower()
    approvals = []

    MAX_UINT256 = 2**256 - 1

    for tx in raw_txs:
        input_data = (tx.get("input") or "").lower()
        if not input_data or input_data == "0x":
            continue

        selector = input_data[:10]
        if selector not in APPROVAL_SELECTORS:
            continue

        method_name = APPROVAL_SELECTORS[selector]
        params_hex = input_data[10:]  # bỏ "0x" + 8 hex của selector

        slot1 = params_hex[0:64] if len(params_hex) >= 64 else ""
        slot2 = params_hex[64:128] if len(params_hex) >= 128 else ""

        owner = tx["from"].lower()
        token_contract = (tx.get("to") or "").lower()
        spender = _decode_address_from_slot(slot1)

        allowance = None
        approved_flag = None
        is_infinite = False

        # ERC20 approve / increase / decrease allowance
        if method_name in ("approve", "increaseAllowance", "decreaseAllowance"):
            if slot2:
                amount_int = _safe_int(slot2)
                allowance = amount_int
                # heuristic: xem như infinite nếu > 2^255
                is_infinite = amount_int > (MAX_UINT256 // 2)

        # ERC721 / ERC1155 setApprovalForAll
        if method_name == "setApprovalForAll":
            if slot2:
                approved_flag = _safe_int(slot2) != 0
                # setApprovalForAll(true) được coi là high risk
                if approved_flag:
                    is_infinite = True

        # ==== heuristic risk level ====
        risk_score = 0.0
        risk_level = "low"

        if method_name == "setApprovalForAll" and approved_flag:
            risk_score = 0.9
            risk_level = "high"
        elif is_infinite:
            risk_score = 0.8
            risk_level = "high"
        elif allowance is not None and allowance > 0:
            risk_score = 0.5
            risk_level = "medium"

        approvals.append(
            {
                "tx_hash": tx["hash"],
                "timestamp": int(tx["timeStamp"]),
                "method": method_name,
                "owner": owner,
                "token_contract": token_contract,
                "spender": spender,
                "allowance": allowance,
                "approved": approved_flag,
                "is_infinite": is_infinite,
                "risk_score": risk_score,
                "risk_level": risk_level,
            }
        )

    return {
        "address": address,
        "approvals": approvals,
        "page": page,
        "limit": limit,
    }
