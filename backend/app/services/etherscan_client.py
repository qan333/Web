"""
Etherscan API Client
Fetches transaction data from Etherscan API
"""
import itertools
import httpx
import logging
from typing import Optional, Dict, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

# Round-robin cycle for Etherscan API keys
_etherscan_keys = settings.etherscan_keys if settings.etherscan_keys else ([settings.etherscan_api_key] if settings.etherscan_api_key else [])
_etherscan_cycle = itertools.cycle(_etherscan_keys) if _etherscan_keys else itertools.cycle([""])

# Shared HTTP client with connection pooling for better performance
_etherscan_client: Optional[httpx.AsyncClient] = None

async def _get_etherscan_client() -> httpx.AsyncClient:
    """Get or create shared HTTP client with connection pooling"""
    global _etherscan_client
    if _etherscan_client is None:
        _etherscan_client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=1.0),  # 5s total, 1s connect (aggressive)
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            http2=True  # HTTP/2 for better performance
        )
    return _etherscan_client

async def etherscan_get(module: str, action: str, chainid: Optional[int] = None, api_key: Optional[str] = None, **params) -> Dict[str, Any]:
    """Send GET request to Etherscan API v2
    
    Args:
        module: API module name
        action: API action name
        chainid: Chain ID (defaults to settings.etherscan_chainid, 1 for Ethereum mainnet, required for v2 API)
        api_key: Optional API key to use (if None, uses round-robin from available keys)
        **params: Additional parameters
    """
    if chainid is None:
        chainid = settings.etherscan_chainid
    # Use provided key or get next from round-robin
    key = api_key if api_key else next(_etherscan_cycle)
    q = {"module": module, "action": action, "apikey": key, "chainid": chainid, **params}
    # Use shared client with connection pooling for better performance
    client = await _get_etherscan_client()
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

async def _fetch_token_transactions(address: str, action: str, tx_type: str, max_txns: int, chainid: Optional[int], api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch token transfers of a specific standard for an address.
    
    Args:
        address: Ethereum address
        action: Etherscan action (tokentx, tokennfttx, token1155tx)
        tx_type: Transaction type (erc20, erc721, erc1155)
        max_txns: Maximum number of transactions to fetch
        chainid: Chain ID
        api_key: Optional API key to use (for load balancing)
    """
    transactions: List[Dict[str, Any]] = []
    page = 1
    offset = 100
    
    while len(transactions) < max_txns:
        result = await etherscan_get(
            "account",
            action,
            chainid=chainid,
            api_key=api_key,  # Pass API key for load balancing
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
    OPTIMIZED: Fetches all token types in parallel with load balancing across multiple API keys.
    
    Args:
        address: Ethereum address
        max_txns: Maximum number of transactions per token type (ERC20, ERC721, ERC1155)
        chainid: Chain ID (1 for Ethereum mainnet)
    
    Returns:
        Combined list of transactions: max 10 total (distributed across ERC20, ERC721, ERC1155)
    """
    import asyncio
    
    # Fetch max transactions for each token type IN PARALLEL
    # Limit to max 10 total transactions (distributed across 3 types)
    # OPTIMIZATION: Explicitly assign different API keys to each task for true load balancing
    max_per_type = 4  # Max 4 per type = max 12 total, but we'll limit to 10 after combining
    num_keys = len(_etherscan_keys) if _etherscan_keys else 1
    
    # Assign API keys explicitly: ERC20 uses key[0], ERC721 uses key[1], ERC1155 uses key[0] again (or key[2] if available)
    erc20_key = _etherscan_keys[0 % num_keys] if _etherscan_keys else None
    erc721_key = _etherscan_keys[1 % num_keys] if _etherscan_keys and num_keys > 1 else _etherscan_keys[0] if _etherscan_keys else None
    erc1155_key = _etherscan_keys[2 % num_keys] if _etherscan_keys and num_keys > 2 else _etherscan_keys[0] if _etherscan_keys else None
    
    erc20_task = _fetch_token_transactions(address, "tokentx", "erc20", max_per_type, chainid, api_key=erc20_key)
    erc721_task = _fetch_token_transactions(address, "tokennfttx", "erc721", max_per_type, chainid, api_key=erc721_key)
    erc1155_task = _fetch_token_transactions(address, "token1155tx", "erc1155", max_per_type, chainid, api_key=erc1155_key)
    
    # Fetch all three types concurrently (each uses a different API key for true parallelization)
    erc20, erc721, erc1155 = await asyncio.gather(erc20_task, erc721_task, erc1155_task, return_exceptions=True)
    
    # Handle exceptions gracefully
    if isinstance(erc20, Exception):
        logger.warning(f"Error fetching ERC20 transactions: {erc20}")
        erc20 = []
    if isinstance(erc721, Exception):
        logger.warning(f"Error fetching ERC721 transactions: {erc721}")
        erc721 = []
    if isinstance(erc1155, Exception):
        logger.warning(f"Error fetching ERC1155 transactions: {erc1155}")
        erc1155 = []
    
    # Combine all transactions and sort by timestamp (newest first)
    combined = erc20 + erc721 + erc1155
    combined.sort(key=lambda tx: tx.get("timestamp", 0), reverse=True)
    
    # Limit to max 10 transactions total
    MAX_TOTAL_TRANSACTIONS = 10
    combined = combined[:MAX_TOTAL_TRANSACTIONS]
    
    # Return limited transactions (max 10 total)
    return combined

