"""
Etherscan API Client
Fetches transaction data from Etherscan API
"""
import itertools
import httpx
from typing import Optional, Dict, Any, List
from app.config import settings

_cycle = itertools.cycle(settings.etherscan_keys or [settings.etherscan_api_key])

async def etherscan_get(module: str, action: str, chainid: Optional[int] = None, **params) -> Dict[str, Any]:
    """Send GET request to Etherscan API v2
    
    Args:
        module: API module name
        action: API action name
        chainid: Chain ID (defaults to settings.etherscan_chainid, 1 for Ethereum mainnet, required for v2 API)
        **params: Additional parameters
    """
    if chainid is None:
        chainid = settings.etherscan_chainid
    key = next(_cycle) if settings.etherscan_keys else settings.etherscan_api_key
    q = {"module": module, "action": action, "apikey": key, "chainid": chainid, **params}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get("https://api.etherscan.io/v2/api", params=q)
        r.raise_for_status()
        return r.json()

async def get_transaction_list(address: str, startblock: int = 0, endblock: int = 99999999, 
                              page: int = 1, offset: int = 100, sort: str = "desc", chainid: Optional[int] = None) -> Dict[str, Any]:
    """Get list of transactions for an address
    
    Args:
        address: Ethereum address
        startblock: Start block number
        endblock: End block number
        page: Page number
        offset: Number of transactions per page
        sort: Sort order (asc/desc)
        chainid: Chain ID (1 for Ethereum mainnet)
    """
    return await etherscan_get(
        "account",
        "txlist",
        chainid=chainid,
        address=address,
        startblock=startblock,
        endblock=endblock,
        page=page,
        offset=offset,
        sort=sort
    )

async def get_transaction_by_hash(tx_hash: str, chainid: Optional[int] = None) -> Dict[str, Any]:
    """Get transaction details by hash
    
    Args:
        tx_hash: Transaction hash
        chainid: Chain ID (1 for Ethereum mainnet)
    """
    result = await etherscan_get("proxy", "eth_getTransactionByHash", chainid=chainid, txhash=tx_hash)
    return result.get("result", {})

async def get_transaction_receipt(tx_hash: str, chainid: Optional[int] = None) -> Dict[str, Any]:
    """Get transaction receipt by hash
    
    Args:
        tx_hash: Transaction hash
        chainid: Chain ID (1 for Ethereum mainnet)
    """
    result = await etherscan_get("proxy", "eth_getTransactionReceipt", chainid=chainid, txhash=tx_hash)
    return result.get("result", {})

async def get_block_by_number(block_number: str, chainid: Optional[int] = None) -> Dict[str, Any]:
    """Get block details by number
    
    Args:
        block_number: Block number (hex string or "latest")
        chainid: Chain ID (1 for Ethereum mainnet)
    """
    result = await etherscan_get("proxy", "eth_getBlockByNumber", chainid=chainid, tag=block_number, boolean="false")
    return result.get("result", {})

def _hex_to_int(x: Optional[str]) -> int:
    """Convert hex string to int"""
    if not x:
        return 0
    try:
        return int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)
    except Exception:
        return 0

# Function signature mapping (common NFT functions)
SIG_MAP = {
    "0x095ea7b3": ("approve", None),
    "0xa22cb465": ("setApprovalForAll", "erc721"),
    "0x23b872dd": ("transferFrom", None),
    "0x42842e0e": ("safeTransferFrom", "erc721"),
    "0xb88d4fde": ("safeTransferFrom", "erc721"),
    "0xf242432a": ("safeBatchTransferFrom", "erc1155"),
    "0x8fcbaf0c": ("permit", "erc20"),
    "0xa9059cbb": ("transfer", "erc20"),
    "0x2eb2c2d6": ("safeTransferFrom", "erc1155"),
}

def decode_function_name(input_data: Optional[str]) -> List[str]:
    """Decode function name from input data"""
    if not input_data or len(input_data) < 10:
        return []
    sel = input_data[:10].lower()
    name = SIG_MAP.get(sel, (None,))[0]
    return [name] if name else []

def _get_token_type_from_input(input_data: Optional[str]) -> Optional[str]:
    """Infer token standard from function selector."""
    if not input_data or len(input_data) < 10:
        return None
    sel = input_data[:10].lower()
    return SIG_MAP.get(sel, (None, None))[1]

def _safe_int(value: Any) -> int:
    """Parse decimal or hex string into int."""
    if value in (None, "", "0x", "0X"):
        return 0
    try:
        value = str(value)
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except (ValueError, TypeError):
        return 0

async def _fetch_token_transactions(address: str, action: str, tx_type: str, max_txns: int, chainid: Optional[int]) -> List[Dict[str, Any]]:
    """Fetch token transfers of a specific standard for an address."""
    transactions: List[Dict[str, Any]] = []
    page = 1
    offset = 100
    
    while len(transactions) < max_txns:
        result = await etherscan_get(
            "account",
            action,
            chainid=chainid,
            address=address,
            page=page,
            offset=offset,
            sort="desc"
        )
        
        if result.get("status") != "1":
            break
        
        txns = result.get("result", [])
        if not isinstance(txns, list) or not txns:
            break
        
        for txn in txns:
            if len(transactions) >= max_txns:
                break
            
            selector_type = _get_token_type_from_input(txn.get("input"))
            inferred_type = selector_type or tx_type
            
            formatted_txn = {
                "from_address": (txn.get("from") or "").lower(),
                "to_address": (txn.get("to") or "").lower(),
                "value": _safe_int(txn.get("value")),
                "gasPrice": _safe_int(txn.get("gasPrice")),
                "gasUsed": _safe_int(txn.get("gasUsed")),
                "timestamp": _safe_int(txn.get("timeStamp")),
                "function_call": decode_function_name(txn.get("input")),
                "transaction_hash": txn.get("hash", ""),
                "blockNumber": _safe_int(txn.get("blockNumber")),
                "contract_address": (txn.get("contractAddress") or txn.get("to") or "").lower(),
                "token_value": _safe_int(txn.get("tokenValue") or txn.get("value")),
                "token_decimal": _safe_int(txn.get("tokenDecimal")),
                "token_id": txn.get("tokenID"),
                "nft_floor_price": 0,
                "nft_average_price": 0,
                "nft_total_volume": 0,
                "nft_total_sales": 0,
                "nft_num_owners": 0,
                "nft_market_cap": 0,
                "nft_7day_volume": 0,
                "nft_7day_sales": 0,
                "nft_7day_avg_price": 0,
                "tx_type": inferred_type or tx_type,
            }
            transactions.append(formatted_txn)
        
        if len(txns) < offset:
            break
        
        page += 1
    
    return transactions

async def get_account_transactions(address: str, max_txns: int = 1000, chainid: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get ERC20/ERC721/ERC1155 transactions for an account address and format them for model input.
    
    Args:
        address: Ethereum address
        max_txns: Maximum number of transactions per token type (ERC20, ERC721, ERC1155)
        chainid: Chain ID (1 for Ethereum mainnet)
    
    Returns:
        Combined list of transactions: max 10 ERC20 + max 10 ERC721 + max 10 ERC1155
    """
    # Fetch max 10 transactions for each token type
    max_per_type = 10
    erc20 = await _fetch_token_transactions(address, "tokentx", "erc20", max_per_type, chainid)
    erc721 = await _fetch_token_transactions(address, "tokennfttx", "erc721", max_per_type, chainid)
    erc1155 = await _fetch_token_transactions(address, "token1155tx", "erc1155", max_per_type, chainid)
    
    # Combine all transactions and sort by timestamp (newest first)
    combined = erc20 + erc721 + erc1155
    combined.sort(key=lambda tx: tx.get("timestamp", 0), reverse=True)
    
    # Return all combined transactions (max 30 total: 10 + 10 + 10)
    return combined

