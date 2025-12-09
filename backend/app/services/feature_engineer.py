"""
Feature Engineering Module
Based on nft_phishing_account_level.py and nft_phishing_transaction_level.py
Extracts features for both account-level and transaction-level classification
"""
import numpy as np
import json
from typing import List, Dict, Any, Optional

def parse_function_calls(func_data) -> List[str]:
    """Parse function_call data to extract function names"""
    if not func_data:
        return []
    if isinstance(func_data, list):
        return func_data
    if isinstance(func_data, str):
        try:
            parsed = json.loads(func_data.replace("'", '"'))
            return parsed if isinstance(parsed, list) else []
        except:
            return []
    return []

def extract_account_level_features(account_address: str, transactions: List[Dict[str, Any]]) -> np.ndarray:
    """
    Extract account-level features (15 features based on AccountLevel_top15_features.json)
    
    Features in order:
    1. avg_gas_price
    2. activity_duration_days
    3. std_time_between_txns
    4. total_volume
    5. inNeighborNum
    6. total_txn
    7. in_out_ratio
    8. total_value_in
    9. outNeighborNum
    10. avg_gas_used
    11. giftinTxn_ratio
    12. miningTxnNum
    13. avg_value_out
    14. turnover_ratio
    15. out_txn
    """
    account_address_lower = account_address.lower()
    
    # Separate in and out transactions
    out_txns = [tx for tx in transactions if tx.get("from_address", "").lower() == account_address_lower]
    in_txns = [tx for tx in transactions if tx.get("to_address", "").lower() == account_address_lower]
    all_txns = transactions
    
    # 1. Average gas price
    gas_prices = [tx.get("gasPrice", 0) for tx in all_txns]
    avg_gas_price = np.mean(gas_prices) if gas_prices else 0
    
    # 2. Activity duration in days
    timestamps = [tx.get("timestamp", 0) for tx in all_txns if tx.get("timestamp", 0) > 0]
    if timestamps and len(timestamps) > 1:
        activity_duration_days = (max(timestamps) - min(timestamps)) / (24 * 3600)
    else:
        activity_duration_days = 0
    
    # 3. Standard deviation of time between transactions
    if len(timestamps) > 1:
        sorted_timestamps = sorted(timestamps)
        time_diffs = np.diff(sorted_timestamps)
        std_time_between_txns = float(np.std(time_diffs)) if len(time_diffs) > 0 else 0
    else:
        std_time_between_txns = 0
    
    # 4. Total volume
    total_volume = sum(tx.get("value", 0) for tx in all_txns)
    
    # 5. Number of unique incoming neighbors
    in_neighbors = set(tx.get("from_address", "").lower() for tx in in_txns if tx.get("from_address"))
    inNeighborNum = len(in_neighbors)
    
    # 6. Total number of transactions
    total_txn = len(all_txns)
    
    # 7. In/Out transaction ratio
    in_out_ratio = len(in_txns) / max(len(out_txns), 1)
    
    # 8. Total value received
    total_value_in = sum(tx.get("value", 0) for tx in in_txns)
    
    # 9. Number of unique outgoing neighbors
    out_neighbors = set(tx.get("to_address", "").lower() for tx in out_txns if tx.get("to_address"))
    outNeighborNum = len(out_neighbors)
    
    # 10. Average gas used
    gas_used = [tx.get("gasUsed", 0) for tx in all_txns]
    avg_gas_used = np.mean(gas_used) if gas_used else 0
    
    # 11. Ratio of gift-in transactions (zero value with token_value > 0)
    gift_in_txns = [tx for tx in in_txns if tx.get("value", 0) == 0 and tx.get("token_value", 0) > 0]
    giftinTxn_ratio = len(gift_in_txns) / max(len(in_txns), 1)
    
    # 12. Number of mining transactions (from zero address)
    mining_txns = [tx for tx in all_txns if tx.get("from_address", "").startswith("0x0000000000000000000000000000000000000000")]
    miningTxnNum = len(mining_txns)
    
    # 13. Average value of outgoing transactions
    avg_value_out = np.mean([tx.get("value", 0) for tx in out_txns]) if out_txns else 0
    
    # 14. Turnover ratio (out_txn / in_txn)
    turnover_ratio = len(out_txns) / max(len(in_txns), 1)
    
    # 15. Number of outgoing transactions
    out_txn = len(out_txns)
    
    # Return features in the exact order specified by feature importance
    features = np.array([
        avg_gas_price,
        activity_duration_days,
        std_time_between_txns,
        total_volume,
        inNeighborNum,
        total_txn,
        in_out_ratio,
        total_value_in,
        outNeighborNum,
        avg_gas_used,
        giftinTxn_ratio,
        miningTxnNum,
        avg_value_out,
        turnover_ratio,
        out_txn,
    ], dtype=np.float32)
    
    return features

def extract_transaction_level_features(transactions: List[Dict[str, Any]]) -> np.ndarray:
    """
    Extract transaction-level features (15 features based on TransactionLevel_top15_features.json)
    
    Features in order:
    1. gas_price
    2. gas_used
    3. value
    4. num_functions
    5. has_suspicious_func
    6. nft_num_owners
    7. nft_total_sales
    8. token_value
    9. nft_total_volume
    10. is_mint
    11. high_gas
    12. nft_average_price
    13. nft_floor_price
    14. nft_market_cap
    15. is_zero_value
    """
    if not transactions:
        return np.zeros(15, dtype=np.float32)
    
    # Aggregate features across all transactions
    gas_prices = [tx.get("gasPrice", 0) for tx in transactions]
    gas_used_list = [tx.get("gasUsed", 0) for tx in transactions]
    values = [tx.get("value", 0) for tx in transactions]
    
    # 1. Average gas price
    gas_price = np.mean(gas_prices) if gas_prices else 0
    
    # 2. Average gas used
    gas_used = np.mean(gas_used_list) if gas_used_list else 0
    
    # 3. Average transaction value
    value = np.mean(values) if values else 0
    
    # 4. Average number of functions
    num_functions_list = []
    for tx in transactions:
        funcs = parse_function_calls(tx.get("function_call", []))
        num_functions_list.append(len(funcs))
    num_functions = np.mean(num_functions_list) if num_functions_list else 0
    
    # 5. Has suspicious functions (average across transactions)
    suspicious_patterns = ['setApprovalForAll', 'approve', 'transferFrom', 'safeTransferFrom',
                          'batchTransfer', 'multiTransfer', 'permit', 'delegateCall']
    
    def has_suspicious_func(tx):
        funcs = parse_function_calls(tx.get("function_call", []))
        return any(pattern.lower() in func.lower() for func in funcs for pattern in suspicious_patterns)
    
    has_suspicious_func_count = sum(1 for tx in transactions if has_suspicious_func(tx))
    has_suspicious_func_ratio = has_suspicious_func_count / len(transactions) if transactions else 0
    
    # 6. Average NFT number of owners
    nft_num_owners = np.mean([tx.get("nft_num_owners", 0) for tx in transactions]) if transactions else 0
    
    # 7. Average NFT total sales
    nft_total_sales = np.mean([tx.get("nft_total_sales", 0) for tx in transactions]) if transactions else 0
    
    # 8. Average token value
    token_value = np.mean([tx.get("token_value", 0) for tx in transactions]) if transactions else 0
    
    # 9. Average NFT total volume
    nft_total_volume = np.mean([tx.get("nft_total_volume", 0) for tx in transactions]) if transactions else 0
    
    # 10. Is mint (ratio of mint transactions)
    is_mint_count = sum(1 for tx in transactions if tx.get("from_address", "").startswith("0x0000000000000000000000000000000000000000"))
    is_mint = is_mint_count / len(transactions) if transactions else 0
    
    # 11. High gas (ratio of transactions above 75th percentile)
    # For single transaction, use a fixed threshold (21000 is standard gas for simple transfer)
    if gas_used_list:
        if len(gas_used_list) == 1:
            # Single transaction: use fixed threshold (21000 = standard transfer, 100000 = high complexity)
            gas_threshold = 100000  # Transactions above 100k gas are considered "high gas"
            high_gas = 1.0 if gas_used_list[0] > gas_threshold else 0.0
        else:
            # Multiple transactions: use 75th percentile
            gas_75th = np.percentile(gas_used_list, 75)
            high_gas_count = sum(1 for g in gas_used_list if g > gas_75th)
            high_gas = high_gas_count / len(gas_used_list)
    else:
        high_gas = 0
    
    # 12. Average NFT average price
    nft_average_price = np.mean([tx.get("nft_average_price", 0) for tx in transactions]) if transactions else 0
    
    # 13. Average NFT floor price
    nft_floor_price = np.mean([tx.get("nft_floor_price", 0) for tx in transactions]) if transactions else 0
    
    # 14. Average NFT market cap
    nft_market_cap = np.mean([tx.get("nft_market_cap", 0) for tx in transactions]) if transactions else 0
    
    # 15. Is zero value (ratio of zero-value transactions)
    is_zero_value_count = sum(1 for tx in transactions if tx.get("value", 0) == 0)
    is_zero_value = is_zero_value_count / len(transactions) if transactions else 0
    
    # Return features in the exact order specified by feature importance
    features = np.array([
        gas_price,
        gas_used,
        value,
        num_functions,
        has_suspicious_func_ratio,
        nft_num_owners,
        nft_total_sales,
        token_value,
        nft_total_volume,
        is_mint,
        high_gas,
        nft_average_price,
        nft_floor_price,
        nft_market_cap,
        is_zero_value,
    ], dtype=np.float32)
    
    return features

