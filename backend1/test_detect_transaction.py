"""
Test script for updated /detect/transaction endpoint
Tests both modes:
1. Manual analysis with transaction hash (fetch from Etherscan)
2. Real-time prevention with pending transaction data (from extension)
"""
import asyncio
import httpx
import json
import sys
from typing import Dict, Any

API_BASE_URL = "http://localhost:8000"


async def test_manual_analysis_mode(tx_hash: str):
    """
    Test Mode 1: Manual analysis with transaction hash
    Simulates UI user inputting a transaction hash for analysis
    Backend will fetch transaction details from Etherscan
    """
    url = f"{API_BASE_URL}/detect/transaction"
    
    payload = {
        "transaction_hash": tx_hash,
        "explain": True,
        "explain_with_llm": True
    }
    
    print("=" * 80)
    print("[MODE 1] MANUAL ANALYSIS - Transaction Hash")
    print("=" * 80)
    print(f"Transaction Hash: {tx_hash}")
    print(f"URL: {url}")
    print(f"Payload:")
    print(json.dumps(payload, indent=2))
    print("-" * 80)
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            
            print(f"\nResponse Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("\n✓ Request successful!")
                print("\nResponse:")
                print(json.dumps(result, indent=2))
                
                # Print key fields
                print("\n" + "-" * 80)
                print("Key Results:")
                print(f"  Detection Mode: {result.get('detection_mode', 'N/A')}")
                print(f"  From: {result.get('account_address', 'N/A')}")
                print(f"  To: {result.get('to_address', 'N/A')}")
                print(f"  Transaction Scam Probability: {result.get('transaction_scam_probability', 'N/A')}")
                
            else:
                print(f"\n✗ Request failed with status {response.status_code}")
                try:
                    error_detail = response.json()
                    print("Error Details:")
                    print(json.dumps(error_detail, indent=2))
                except:
                    print(f"Error Text: {response.text}")
                    
    except httpx.TimeoutException:
        print("\n✗ Request timed out (>60s)")
    except Exception as e:
        print(f"\n✗ Unexpected error: {type(e).__name__}: {str(e)}")


async def test_pending_transaction_mode(
    from_address: str,
    to_address: str,
    value: str = "0",
    gasPrice: str = "20000000000",
    gasUsed: str = "100000",
    contract_address: str = None,
    function_call: list = None,
    input_data: str = None
):
    """
    Test Mode 2: Real-time prevention with pending transaction
    Simulates extension intercepting a pending transaction before user signs
    Backend will use provided data directly (no Etherscan call)
    """
    url = f"{API_BASE_URL}/detect/transaction"
    
    payload = {
        "from_address": from_address,
        "to_address": to_address,
        "value": value,
        "gasPrice": gasPrice,
        "gasUsed": gasUsed,
        "explain": True,
        "explain_with_llm": True,
    }
    
    if contract_address:
        payload["contract_address"] = contract_address
    
    if function_call:
        payload["function_call"] = function_call
        
    if input_data:
        payload["input"] = input_data
    
    print("=" * 80)
    print("[MODE 2] REAL-TIME PREVENTION - Pending Transaction")
    print("=" * 80)
    print(f"From: {from_address}")
    print(f"To: {to_address}")
    print(f"Value: {value} wei")
    print(f"Gas Price: {gasPrice}")
    print(f"URL: {url}")
    print(f"Payload:")
    print(json.dumps(payload, indent=2))
    print("-" * 80)
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            
            print(f"\nResponse Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("\n✓ Request successful!")
                print("\nResponse:")
                print(json.dumps(result, indent=2))
                
                # Print key fields
                print("\n" + "-" * 80)
                print("Key Results:")
                print(f"  Detection Mode: {result.get('detection_mode', 'N/A')}")
                print(f"  From: {result.get('account_address', 'N/A')}")
                print(f"  To: {result.get('to_address', 'N/A')}")
                print(f"  Transaction Scam Probability: {result.get('transaction_scam_probability', 'N/A')}")
                
                if "explanations" in result and result["explanations"].get("transaction"):
                    tx_expl = result["explanations"]["transaction"]
                    print(f"\n  Top Features (Transaction):")
                    for feat in tx_expl.get('feature_importance', [])[:5]:
                        print(f"    - {feat['feature']}: {feat['value']:.4f} (SHAP: {feat['shap_value']:.4f})")
                
            else:
                print(f"\n✗ Request failed with status {response.status_code}")
                try:
                    error_detail = response.json()
                    print("Error Details:")
                    print(json.dumps(error_detail, indent=2))
                except:
                    print(f"Error Text: {response.text}")
                    
    except httpx.TimeoutException:
        print("\n✗ Request timed out (>60s)")
    except Exception as e:
        print(f"\n✗ Unexpected error: {type(e).__name__}: {str(e)}")


async def main():
    """Run test cases for both modes"""
    
    print("\n" + "=" * 80)
    print("TRANSACTION DETECTION TEST SUITE - UPDATED")
    print("=" * 80)
    print("\nTesting 2 modes:")
    print("1. Manual Analysis (UI) - fetch from Etherscan by hash")
    print("2. Real-time Prevention (Extension) - analyze pending transaction")
    print("=" * 80)
    
    # =========================================================================
    # MODE 1: MANUAL ANALYSIS TESTS
    # =========================================================================
    
    print("\n\n" + "🔍 " + "=" * 76)
    print("MODE 1 TESTS: MANUAL ANALYSIS WITH TRANSACTION HASH")
    print("=" * 80)
    
    # Test 1.1: Real transaction hash (replace with actual hash from Etherscan)
    print("\n\n[Test 1.1] Manual analysis - Real transaction")
    # Note: Replace with a real transaction hash from Ethereum mainnet
    await test_manual_analysis_mode(
        tx_hash="0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234"
    )
    
    await asyncio.sleep(2)
    
    # =========================================================================
    # MODE 2: REAL-TIME PREVENTION TESTS
    # =========================================================================
    
    print("\n\n" + "⚡ " + "=" * 76)
    print("MODE 2 TESTS: REAL-TIME PREVENTION WITH PENDING TRANSACTION")
    print("=" * 80)
    
    # Test 2.1: Normal ETH transfer (pending)
    print("\n\n[Test 2.1] Pending transaction - Normal ETH transfer")
    await test_pending_transaction_mode(
        from_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        to_address="0x8ba1f109551bD432803012645Ac136ddd64DBA72",
        value="1000000000000000000",  # 1 ETH
        gasPrice="30000000000",  # 30 Gwei
        gasUsed="21000",
    )
    
    await asyncio.sleep(2)
    
    # Test 2.2: NFT Transfer with suspicious function (pending)
    print("\n\n[Test 2.2] Pending transaction - NFT transfer with setApprovalForAll")
    await test_pending_transaction_mode(
        from_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        to_address="0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",  # BAYC
        value="0",
        gasPrice="100000000000",  # High gas - 100 Gwei
        gasUsed="150000",
        contract_address="0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        function_call=["setApprovalForAll", "approve"],
    )
    
    await asyncio.sleep(2)
    
    # Test 2.3: Suspicious transaction with input data decoding (pending)
    print("\n\n[Test 2.3] Pending transaction - with input data (auto-decode functions)")
    await test_pending_transaction_mode(
        from_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        to_address="0x1234567890123456789012345678901234567890",
        value="0",
        gasPrice="50000000000",
        gasUsed="100000",
        input_data="0xa22cb465000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # setApprovalForAll
    )
    
    await asyncio.sleep(2)
    
    # Test 2.4: Zero value transfer (pending)
    print("\n\n[Test 2.4] Pending transaction - Zero value transfer")
    await test_pending_transaction_mode(
        from_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        to_address="0x5555555555555555555555555555555555555555",
        value="0",
        gasPrice="20000000000",
        gasUsed="21000",
    )
    
    print("\n" + "=" * 80)
    print("✓ All test cases completed!")
    print("=" * 80)
    print("\nSummary:")
    print("- Mode 1 (Manual Analysis): Backend fetches from Etherscan API")
    print("- Mode 2 (Real-time Prevention): Backend uses provided data directly")
    print("- NFT enrichment via Rarible API happens in both modes")
    print("=" * 80)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠ Tests interrupted by user")
        sys.exit(1)

