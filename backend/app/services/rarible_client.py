"""
Rarible API Client
Fetches NFT collection data from Rarible API
"""
import os
import itertools
import asyncio
import httpx
import logging
import time
from typing import Optional, Dict, Any, Set, List
from app.config import settings

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("RARIBLE_BASE_URL", "https://api.rarible.org/v0.1")

# Support multiple Rarible API keys for load balancing
RARIBLE_API_KEYS = settings.rarible_api_keys if settings.rarible_api_keys else ([settings.rarible_api_key] if settings.rarible_api_key else [])
_rarible_cycle = itertools.cycle(RARIBLE_API_KEYS) if RARIBLE_API_KEYS else itertools.cycle([""])

_DEFAULT_TIMEOUT = httpx.Timeout(1.5, connect=0.5)  # Very aggressive timeout: 1.5s total, 0.5s connect (fail fast)

# Cache for collections that don't exist (404) to avoid repeated API calls
_NOT_FOUND_CACHE: Set[str] = set()

# Shared HTTP client with connection pooling for better performance
_rarible_client: Optional[httpx.AsyncClient] = None

async def _get_rarible_client() -> httpx.AsyncClient:
    """Get or create shared HTTP client with connection pooling"""
    global _rarible_client
    if _rarible_client is None:
        _rarible_client = httpx.AsyncClient(
            timeout=_DEFAULT_TIMEOUT,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            http2=True  # HTTP/2 for better performance
        )
    return _rarible_client

async def rarible_get(path: str, params: Optional[Dict[str, Any]] = None, allow_404: bool = False, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Send GET request to Rarible API with load balancing across multiple API keys
    
    Args:
        path: API path
        params: Query parameters
        allow_404: If True, return None for 404 instead of raising exception
        api_key: Optional API key to use (if None, uses round-robin from available keys)
    
    Returns:
        JSON response or None if 404 and allow_404=True
    """
    if not RARIBLE_API_KEYS:
        raise RuntimeError("RARIBLE_API_KEY or RARIBLE_API_KEYS not set")
    
    # Use provided key or get next from round-robin
    key = api_key if api_key else next(_rarible_cycle)
    
    headers = {
        "accept": "application/json",
        "x-api-key": key,
    }
    
    url = f"{BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    start_time = time.time()
    # Use shared client with connection pooling for better performance
    client = await _get_rarible_client()
    r = await client.get(url, params=params or {}, headers=headers)
    elapsed = time.time() - start_time
    
    # Handle 404 gracefully if allowed
    if r.status_code == 404 and allow_404:
        logger.debug(f"⏱️ [TIMING] Rarible API {path}: {elapsed:.2f}s (Status: 404 - Not Found)")
        return None
    
    # Debug: Print response details if error
    if r.status_code != 200:
        logger.warning(f"⏱️ [TIMING] Rarible API {path}: {elapsed:.2f}s (Status: {r.status_code})")
        if r.status_code == 404:
            logger.debug(f"   Collection not found: {path}")
    else:
        logger.debug(f"⏱️ [TIMING] Rarible API {path}: {elapsed:.2f}s")
    
    r.raise_for_status()
    return r.json()

async def items_by_owner(
    owner: str,
    blockchain: str = "ETHEREUM",
    size: int = 20,
    continuation: Optional[str] = None,
) -> Dict[str, Any]:
    """Get items owned by an address"""
    owner_full = f"{blockchain}:{owner}"
    params: Dict[str, Any] = {"owner": owner_full, "size": size}
    if continuation:
        params["continuation"] = continuation
    return await rarible_get("items/byOwner", params=params)

async def collection_by_id(collection_id: str) -> Dict[str, Any]:
    """Get collection by ID"""
    return await rarible_get(f"collections/{collection_id}")

async def collection_statistics(collection_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Get NFT Collection statistics from Rarible API v0.1
    
    Args:
        collection_id: Collection ID in format "ETHEREUM:{contract_address}"
        api_key: Optional API key to use (for load balancing)
    
    Returns:
        Dictionary with statistics or None if collection not found (404):
        - listed: Number of listed items
        - items: Total number of items
        - owners: Number of owners
        - highestSale: [{"currency": "USD|ETH", "value": float}, ...]
        - floorPrice: [{"currency": "USD|ETH", "value": float}, ...]
        - marketCap: [{"currency": "USD|ETH", "value": float}, ...]
        - volume: [{"currency": "USD|ETH", "value": float}, ...]
    """
    return await rarible_get(f"data/collections/{collection_id}/statistics", allow_404=True, api_key=api_key)

async def item_by_id(item_id: str) -> Dict[str, Any]:
    """Get item by ID"""
    return await rarible_get(f"items/{item_id}")

def _extract_eth_value(price_list: list) -> float:
    """
    Extract ETH value from price list
    Price list format: [{"currency": "USD", "value": float}, {"currency": "ETH", "value": float}]
    """
    if not price_list or not isinstance(price_list, list):
        return 0.0
    
    for item in price_list:
        if isinstance(item, dict) and item.get("currency", "").upper() == "ETH":
            value = item.get("value", 0)
            try:
                return float(value) if value is not None else 0.0
            except (ValueError, TypeError):
                return 0.0
    
    # Fallback to USD if ETH not found (convert assuming 1 ETH = 2000 USD for estimation)
    # This is just a fallback, ideally should always have ETH
    for item in price_list:
        if isinstance(item, dict) and item.get("currency", "").upper() == "USD":
            value = item.get("value", 0)
            try:
                usd_value = float(value) if value is not None else 0.0
                # Rough conversion (this should ideally come from API or use a price feed)
                return usd_value / 2000.0 if usd_value > 0 else 0.0
            except (ValueError, TypeError):
                return 0.0
    
    return 0.0

def _set_default_nft_fields(transaction: Dict[str, Any]) -> None:
    """Set all NFT-related fields to 0 (default values)"""
    transaction["nft_num_owners"] = 0
    transaction["nft_total_sales"] = 0
    transaction["nft_floor_price"] = 0
    transaction["nft_market_cap"] = 0
    transaction["nft_total_volume"] = 0
    transaction["nft_average_price"] = 0
    transaction["nft_7day_volume"] = 0
    transaction["nft_7day_sales"] = 0
    transaction["nft_7day_avg_price"] = 0

async def enrich_transaction_with_nft_data(transaction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich transaction with NFT collection metrics from Rarible using the statistics API
    
    Uses: GET https://api.rarible.org/v0.1/data/collections/{collection}/statistics
    
    If collection not found (404), sets all NFT fields to 0 and caches the result
    to avoid repeated API calls for the same non-existent collection.
    """
    contract_address = transaction.get("contract_address", "")
    if not contract_address or contract_address == "":
        _set_default_nft_fields(transaction)
        return transaction
    
    enrich_start = time.time()
    collection_id = f"ETHEREUM:{contract_address}"
    
    # Check cache first - if collection was previously not found, skip API call
    if collection_id in _NOT_FOUND_CACHE:
        logger.debug(f"⏱️ [CACHE] Collection {contract_address[:10]}... already known as not found, skipping API call")
        _set_default_nft_fields(transaction)
        enrich_time = time.time() - enrich_start
        logger.debug(f"⏱️ [TIMING] NFT enrichment (cached) for {contract_address[:10]}...: {enrich_time:.3f}s")
        return transaction
    
    try:
        # Get collection statistics using the new API endpoint
        stats = await collection_statistics(collection_id)
        
        if stats is None:
            # Collection not found (404) - cache it and set defaults
            _NOT_FOUND_CACHE.add(collection_id)
            logger.debug(f"⏱️ [CACHE] Caching not-found collection: {contract_address[:10]}...")
            _set_default_nft_fields(transaction)
        else:
            # Collection found - extract values, preferring ETH currency
            transaction["nft_num_owners"] = stats.get("owners", 0) or 0
            transaction["nft_total_sales"] = stats.get("items", 0) or 0  # Using items as total sales indicator
            transaction["nft_floor_price"] = _extract_eth_value(stats.get("floorPrice", []))
            transaction["nft_market_cap"] = _extract_eth_value(stats.get("marketCap", []))
            transaction["nft_total_volume"] = _extract_eth_value(stats.get("volume", []))
            
            # Use highestSale as average price indicator, or calculate from volume/sales
            highest_sale = _extract_eth_value(stats.get("highestSale", []))
            if highest_sale > 0:
                transaction["nft_average_price"] = highest_sale
            else:
                # Fallback: estimate from volume/sales if available
                volume = transaction.get("nft_total_volume", 0)
                sales = transaction.get("nft_total_sales", 0)
                if sales > 0 and volume > 0:
                    transaction["nft_average_price"] = volume / sales
                else:
                    transaction["nft_average_price"] = transaction.get("nft_floor_price", 0)
            
            # Set 7-day metrics to 0 (not available in current API response)
            transaction["nft_7day_volume"] = 0
            transaction["nft_7day_sales"] = 0
            transaction["nft_7day_avg_price"] = 0
            
    except Exception as e:
        # For any other error (not 404), log and set defaults
        logger.warning(f"Error enriching NFT data for {contract_address[:10]}...: {e}")
        _set_default_nft_fields(transaction)
    finally:
        enrich_time = time.time() - enrich_start
        logger.debug(f"⏱️ [TIMING] NFT enrichment for {contract_address[:10]}...: {enrich_time:.3f}s")
    
    return transaction

async def enrich_transactions_with_nft_data(transactions: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """
    Enrich a list of transactions with NFT data - OPTIMIZED with parallel API calls
    
    Uses asyncio.gather to fetch all collection statistics in parallel instead of sequentially.
    This reduces total time from O(n) to O(1) where n is number of unique collections.
    """
    import asyncio
    
    if not transactions:
        return []
    
    # Group transactions by contract_address to avoid duplicate API calls
    # OPTIMIZATION: Skip ERC20 transactions (they don't need NFT enrichment)
    contract_to_txns: Dict[str, List[Dict[str, Any]]] = {}
    for txn in transactions:
        tx_type = txn.get("tx_type", "").lower()
        contract_address = txn.get("contract_address", "")
        
        # Skip ERC20 transactions - they don't need NFT data
        if tx_type == "erc20":
            _set_default_nft_fields(txn)
            continue
        
        if contract_address and contract_address != "":
            if contract_address not in contract_to_txns:
                contract_to_txns[contract_address] = []
            contract_to_txns[contract_address].append(txn)
        else:
            # No contract address - set defaults immediately
            _set_default_nft_fields(txn)
    
    # Fetch all unique collection statistics in parallel
    collection_ids = [f"ETHEREUM:{addr}" for addr in contract_to_txns.keys()]
    
    # Log for debugging
    if collection_ids:
        logger.debug(f"⏱️ [RARIBLE] Fetching {len(collection_ids)} unique collections: {[cid.split(':')[1][:10] + '...' for cid in collection_ids[:5]]}")
    
    # Filter out already cached (not found) collections
    uncached_collections = [cid for cid in collection_ids if cid not in _NOT_FOUND_CACHE]
    
    if uncached_collections:
        logger.debug(f"⏱️ [RARIBLE] {len(uncached_collections)} uncached collections, {len(collection_ids) - len(uncached_collections)} cached")
    
    if uncached_collections:
        # Fetch all statistics in parallel with load balancing across API keys
        # Distribute collections across available API keys
        num_keys = len(RARIBLE_API_KEYS) if RARIBLE_API_KEYS else 1
        tasks = []
        for i, cid in enumerate(uncached_collections):
            # Round-robin assignment: use key index based on collection index
            api_key = RARIBLE_API_KEYS[i % num_keys] if RARIBLE_API_KEYS else None
            tasks.append(collection_statistics(cid, api_key=api_key))
        
        try:
            # All calls run in parallel with aggressive timeout protection
            # Set overall timeout to 2s (matching individual timeout of 1.5s + overhead)
            stats_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=2.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"Rarible API calls timed out after 2s for {len(uncached_collections)} collections")
            # When timeout occurs, gather() will cancel all pending tasks automatically
            # Return None for all timed-out calls
            stats_results = [None] * len(uncached_collections)
        except Exception as e:
            logger.warning(f"Error in parallel Rarible API calls: {e}")
            stats_results = [None] * len(uncached_collections)
    else:
        stats_results = []
    
    # Map results back to collection IDs
    stats_map: Dict[str, Optional[Dict[str, Any]]] = {}
    for i, cid in enumerate(uncached_collections):
        result = stats_results[i] if i < len(stats_results) else None
        if isinstance(result, Exception):
            logger.warning(f"Error fetching stats for {cid}: {result}")
            stats_map[cid] = None
        else:
            stats_map[cid] = result
            # Cache 404 results
            if result is None:
                _NOT_FOUND_CACHE.add(cid)
    
    # Apply statistics to all transactions with matching contract addresses
    enriched = []
    for txn in transactions:
        contract_address = txn.get("contract_address", "")
        if not contract_address or contract_address == "":
            enriched.append(txn)
            continue
        
        collection_id = f"ETHEREUM:{contract_address}"
        
        # Check cache first
        if collection_id in _NOT_FOUND_CACHE:
            _set_default_nft_fields(txn)
            enriched.append(txn)
            continue
        
        # Get statistics from map
        stats = stats_map.get(collection_id)
        
        if stats is None:
            # Collection not found - cache and set defaults
            _NOT_FOUND_CACHE.add(collection_id)
            _set_default_nft_fields(txn)
        else:
            # Collection found - extract values
            txn["nft_num_owners"] = stats.get("owners", 0) or 0
            txn["nft_total_sales"] = stats.get("items", 0) or 0
            txn["nft_floor_price"] = _extract_eth_value(stats.get("floorPrice", []))
            txn["nft_market_cap"] = _extract_eth_value(stats.get("marketCap", []))
            txn["nft_total_volume"] = _extract_eth_value(stats.get("volume", []))
            
            highest_sale = _extract_eth_value(stats.get("highestSale", []))
            if highest_sale > 0:
                txn["nft_average_price"] = highest_sale
            else:
                volume = txn.get("nft_total_volume", 0)
                sales = txn.get("nft_total_sales", 0)
                if sales > 0 and volume > 0:
                    txn["nft_average_price"] = volume / sales
                else:
                    txn["nft_average_price"] = txn.get("nft_floor_price", 0)
            
            txn["nft_7day_volume"] = 0
            txn["nft_7day_sales"] = 0
            txn["nft_7day_avg_price"] = 0
        
        enriched.append(txn)
    
    return enriched

