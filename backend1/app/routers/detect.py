"""
Detection Router
Main endpoint for account detection
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from app.services.detection_service import DetectionService
from app.services.etherscan_client import get_transaction_by_hash, get_transaction_receipt, decode_function_name
import logging
import time

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/detect", tags=["detect"])

# Initialize detection service (loaded at startup)
_detection_service = None

def parse_int_value(value: Optional[str]) -> int:
    """
    Parse integer value from string, supporting both decimal and hexadecimal formats.
    
    Args:
        value: String value to parse (e.g., "1000", "0x3e8", "0")
    
    Returns:
        Integer value
    
    Examples:
        parse_int_value("1000") -> 1000
        parse_int_value("0x3e8") -> 1000
        parse_int_value("0x0") -> 0
        parse_int_value(None) -> 0
    """
    if not value or value == "0":
        return 0
    
    try:
        # Check if it's hexadecimal format (starts with 0x or 0X)
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)  # Parse as hexadecimal
        else:
            return int(value, 10)  # Parse as decimal
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse value '{value}': {e}. Defaulting to 0")
        return 0

def get_detection_service() -> DetectionService:
    """Get or initialize detection service"""
    global _detection_service
    if _detection_service is None:
        logger.info("Initializing DetectionService...")
        try:
            _detection_service = DetectionService()
            logger.info("DetectionService initialized successfully")
        except Exception as e:
            logger.exception(f"Failed to initialize DetectionService: {str(e)}")
            raise
    return _detection_service

async def fetch_transaction_from_etherscan(tx_hash: str) -> Dict[str, Any]:
    """
    Fetch transaction details from Etherscan by hash
    
    Args:
        tx_hash: Transaction hash
        
    Returns:
        Formatted transaction data
    """
    logger.info(f"Fetching transaction from Etherscan: {tx_hash}")
    
    # Fetch transaction details and receipt
    tx_data = await get_transaction_by_hash(tx_hash)
    tx_receipt = await get_transaction_receipt(tx_hash)
    
    if not tx_data:
        raise HTTPException(status_code=404, detail=f"Transaction {tx_hash} not found on Etherscan")
    
    # Parse transaction data
    from_address = (tx_data.get("from") or "").lower()
    to_address = (tx_data.get("to") or "").lower()
    value = parse_int_value(tx_data.get("value", "0"))
    gas_price = parse_int_value(tx_data.get("gasPrice", "0"))
    gas_used = parse_int_value(tx_receipt.get("gasUsed", "0"))
    block_number = parse_int_value(tx_data.get("blockNumber", "0"))
    input_data = tx_data.get("input", "0x")
    
    # Decode function calls from input data
    function_calls = decode_function_name(input_data)
    
    # Get timestamp from block (approximate - using current time as fallback)
    timestamp = int(time.time())
    
    # Determine contract address and transaction type
    contract_address = to_address
    is_nft_tx = input_data and input_data != "0x" and len(input_data) > 10
    
    formatted_txn = {
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
        "token_value": 0,  # Will be enriched by Rarible API
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
    
    logger.info(f"Transaction fetched: from={from_address}, to={to_address}, value={value}, gas_price={gas_price}, gas_used={gas_used}, functions={function_calls}")
    logger.debug(f"[DEBUG] Transaction data: {formatted_txn}")
    return formatted_txn

class DetectIn(BaseModel):
    account_address: str = Field(..., description="Ethereum address to analyze")
    explain: bool = Field(False, description="Include SHAP explanations")
    explain_with_llm: bool = Field(False, description="Include LLM explanations (requires explain=True)")
    max_transactions: int = Field(1000, description="Maximum number of transactions to fetch")

class DetectTransactionIn(BaseModel):
    # Option 1: Manual analysis - provide transaction hash
    transaction_hash: Optional[str] = Field(None, description="Transaction hash for manual analysis (will fetch from Etherscan)")
    
    # Option 2: Pending transaction - provide transaction details
    from_address: Optional[str] = Field(None, description="From address (for pending transaction)")
    to_address: Optional[str] = Field(None, description="To address (for pending transaction)")
    value: Optional[str] = Field(None, description="Transaction value in wei (for pending transaction)")
    gasPrice: Optional[str] = Field(None, description="Gas price (for pending transaction)")
    gasUsed: Optional[str] = Field(None, description="Gas used (for pending transaction)")
    timestamp: Optional[int] = Field(None, description="Transaction timestamp (for pending transaction)")
    function_call: Optional[List[str]] = Field(None, description="Function calls in transaction (for pending transaction)")
    input: Optional[str] = Field(None, description="Input data (for pending transaction)")
    contract_address: Optional[str] = Field(None, description="Contract address (if NFT transfer)")
    token_value: Optional[str] = Field(None, description="Token/NFT value")
    
    # Common options
    explain: bool = Field(True, description="Include SHAP explanations")
    explain_with_llm: bool = Field(True, description="Include LLM explanations")

@router.post("/transaction")
async def detect_transaction(body: DetectTransactionIn):
    """
    Detect phishing/scam activity for a single transaction
    
    Two modes:
    1. Manual analysis (UI): Provide transaction_hash → fetch from Etherscan
    2. Real-time prevention (Extension): Provide transaction details → analyze pending transaction
    """
    try:
        transaction_data = None
        
        # Mode 1: Manual analysis with transaction hash
        if body.transaction_hash:
            logger.info(f"[MANUAL ANALYSIS] Transaction hash: {body.transaction_hash}")
            transaction_data = await fetch_transaction_from_etherscan(body.transaction_hash)
            logger.info(f"Transaction fetched from Etherscan: from={transaction_data['from_address']}, to={transaction_data['to_address']}")
        
        # Mode 2: Real-time prevention with pending transaction data
        elif body.from_address and body.to_address:
            logger.info(f"[PENDING TRANSACTION] from={body.from_address}, to={body.to_address}, value={body.value}")
            
            # Parse function calls from input data if provided
            function_calls = body.function_call if body.function_call else []
            if not function_calls and body.input:
                function_calls = decode_function_name(body.input)
            
            transaction_data = {
                "from_address": body.from_address.lower(),
                "to_address": body.to_address.lower(),
                "value": parse_int_value(body.value) if body.value else 0,
                "gasPrice": parse_int_value(body.gasPrice) if body.gasPrice else 0,
                "gasUsed": parse_int_value(body.gasUsed) if body.gasUsed else 0,
                "timestamp": body.timestamp if body.timestamp else int(time.time()),
                "function_call": function_calls,
                "contract_address": (body.contract_address or body.to_address).lower(),
                "token_value": parse_int_value(body.token_value) if body.token_value else 0,
                "transaction_hash": "",  # No hash for pending transaction
                "blockNumber": 0,  # Not mined yet
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
            logger.info(f"Pending transaction prepared: functions={function_calls}, gas_price={transaction_data['gasPrice']}")
        
        else:
            raise HTTPException(
                status_code=400, 
                detail="Either 'transaction_hash' (for manual analysis) or 'from_address' + 'to_address' (for pending transaction) must be provided"
            )
        
        # Call detection service (NFT enrichment will happen inside)
        detection_start = time.time()
        detection_service = get_detection_service()
        result = await detection_service.detect_transaction(
            transaction_data=transaction_data,
            explain=body.explain,
            explain_with_llm=body.explain_with_llm
        )
        detection_time = time.time() - detection_start
        
        logger.info(f"Transaction detection completed: prob={result.get('transaction_scam_probability'):.4f}, mode={result.get('detection_mode')}")
        logger.info(f"⏱️ [TIMING] Total endpoint time: {detection_time:.2f}s")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Transaction detection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Transaction detection failed: {str(e)}")

async def _handle_account_detection(body: DetectIn):
    """Shared implementation for account detection endpoints."""
    logger.info(f"Account detection request: address={body.account_address}, explain={body.explain}, explain_llm={body.explain_with_llm}")
    
    if body.explain_with_llm and not body.explain:
        raise HTTPException(
            status_code=400,
            detail="explain must be True when explain_with_llm is True"
        )
    
    detection_start = time.time()
    detection_service = get_detection_service()
    result = await detection_service.detect_account(
        account_address=body.account_address,
        explain=body.explain,
        explain_with_llm=body.explain_with_llm,
        max_transactions=body.max_transactions
    )
    detection_time = time.time() - detection_start
    
    logger.info(f"Account detection completed: address={body.account_address}, mode={result.get('detection_mode')}")
    logger.info(f"⏱️ [TIMING] Total endpoint time: {detection_time:.2f}s")
    return result

@router.post("/account")
async def detect_account(body: DetectIn):
    """
    Detect phishing/scam activity for an account address
    
    Flow:
    1. Fetch transactions from Etherscan API
    2. Enrich with NFT data from Rarible API
    3. Extract features (account-level and transaction-level)
    4. Make predictions using MTL_MLP model
    5. Generate SHAP explanations (if explain=True)
    6. Generate LLM explanations (if explain_with_llm=True)
    """
    try:
        return await _handle_account_detection(body)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Account detection failed for {body.account_address}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@router.post("")
async def detect(body: DetectIn):
    """Legacy endpoint kept for backward compatibility."""
    return await _handle_account_detection(body)

