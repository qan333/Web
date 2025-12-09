"""
Test script for account-task detection endpoint
Tests the full flow:
1. Fetch ERC721 and ERC1155 transactions from Etherscan
2. Enrich with NFT data from Rarible API
3. Feature engineering (account-level and transaction-level)
4. Model prediction (account and transaction probabilities)
5. SHAP explanation
6. LLM explanation
"""
import asyncio
import httpx
import json
import sys
from typing import Dict, Any

API_BASE_URL = "http://localhost:8000"


async def test_account_detection(
    account_address: str,
    explain: bool = True,
    explain_with_llm: bool = True,
    max_transactions: int = 1000
):
    """
    Test account-task detection endpoint
    
    Flow:
    1. Backend fetches ERC721 and ERC1155 transactions from Etherscan
    2. Enriches each transaction with NFT pricing data from Rarible
    3. Extracts account-level and transaction-level features
    4. Makes predictions using multi-task model
    5. Generates SHAP explanations
    6. Generates LLM explanations
    """
    url = f"{API_BASE_URL}/detect/account"
    
    payload = {
        "account_address": account_address,
        "explain": explain,
        "explain_with_llm": explain_with_llm,
        "max_transactions": max_transactions
    }
    
    print("=" * 80)
    print("ACCOUNT-TASK DETECTION TEST")
    print("=" * 80)
    print(f"Account Address: {account_address}")
    print(f"URL: {url}")
    print(f"Payload:")
    print(json.dumps(payload, indent=2))
    print("-" * 80)
    print("\n📊 Expected Flow:")
    print("  1. Fetch ERC721 & ERC1155 transactions from Etherscan")
    print("  2. Enrich transactions with NFT data from Rarible API")
    print("  3. Feature engineering (account-level + transaction-level)")
    print("  4. Model prediction (account + transaction probabilities)")
    print("  5. SHAP explanation (feature importance)")
    print("  6. LLM explanation (human-readable)")
    print("-" * 80)
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            print("\n⏳ Sending request to backend...")
            response = await client.post(url, json=payload)
            
            print(f"\nResponse Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("\n✓ Request successful!")
                
                # Print detection mode
                print("\n" + "=" * 80)
                print("DETECTION MODE")
                print("=" * 80)
                detection_mode = result.get('detection_mode', 'N/A')
                print(f"Mode: {detection_mode}")
                
                if detection_mode == 'no_data':
                    print("\n⚠️  No transactions found for this address")
                    print(f"Message: {result.get('message', 'N/A')}")
                    return
                
                # Print transaction count
                print(f"Transactions Analyzed: {result.get('transactions_count', 0)}")
                
                # Print predictions
                print("\n" + "=" * 80)
                print("MODEL PREDICTIONS")
                print("=" * 80)
                account_prob = result.get('account_scam_probability')
                transaction_prob = result.get('transaction_scam_probability')
                
                if account_prob is not None:
                    risk_level = "HIGH" if account_prob > 0.7 else "MEDIUM" if account_prob > 0.4 else "LOW"
                    print(f"Account Scam Probability: {account_prob:.6f} ({account_prob*100:.2f}%) [{risk_level} RISK]")
                else:
                    print("Account Scam Probability: N/A")
                
                if transaction_prob is not None:
                    risk_level = "HIGH" if transaction_prob > 0.7 else "MEDIUM" if transaction_prob > 0.4 else "LOW"
                    print(f"Transaction Scam Probability: {transaction_prob:.6f} ({transaction_prob*100:.2f}%) [{risk_level} RISK]")
                else:
                    print("Transaction Scam Probability: N/A")
                
                # Print SHAP explanations
                if explain and 'explanations' in result:
                    print("\n" + "=" * 80)
                    print("SHAP EXPLANATIONS (Feature Importance)")
                    print("=" * 80)
                    
                    # Account-level SHAP
                    if result['explanations'].get('account'):
                        account_expl = result['explanations']['account']
                        print("\n📊 Account-Level Features (Top 10):")
                        feature_importance = account_expl.get('feature_importance', [])
                        for i, feat in enumerate(feature_importance[:10], 1):
                            feature_name = feat.get('feature_name', feat.get('feature', 'Unknown'))
                            feature_value = feat.get('feature_value', feat.get('value', 0))
                            shap_value = feat.get('shap_value', 0)
                            impact = "↑ Increases risk" if shap_value > 0 else "↓ Decreases risk"
                            print(f"  {i:2d}. {feature_name:40s} = {feature_value:12.6f}  SHAP: {shap_value:10.6f}  {impact}")
                    
                    # Transaction-level SHAP
                    if result['explanations'].get('transaction'):
                        transaction_expl = result['explanations']['transaction']
                        print("\n⚡ Transaction-Level Features (Top 10):")
                        feature_importance = transaction_expl.get('feature_importance', [])
                        for i, feat in enumerate(feature_importance[:10], 1):
                            feature_name = feat.get('feature_name', feat.get('feature', 'Unknown'))
                            feature_value = feat.get('feature_value', feat.get('value', 0))
                            shap_value = feat.get('shap_value', 0)
                            impact = "↑ Increases risk" if shap_value > 0 else "↓ Decreases risk"
                            print(f"  {i:2d}. {feature_name:40s} = {feature_value:12.6f}  SHAP: {shap_value:10.6f}  {impact}")
                
                # Print LLM explanations
                if explain_with_llm and 'llm_explanations' in result:
                    print("\n" + "=" * 80)
                    print("LLM EXPLANATIONS (Human-Readable)")
                    print("=" * 80)
                    
                    # Account-level LLM
                    if result['llm_explanations'].get('account'):
                        account_llm = result['llm_explanations']['account']
                        print("\n📝 Account Risk Analysis:")
                        if isinstance(account_llm, dict):
                            print(f"  Feature: {account_llm.get('feature_name', 'N/A')}")
                            print(f"  Value: {account_llm.get('feature_value', 'N/A')}")
                            print(f"  Explanation: {account_llm.get('reason', 'N/A')}")
                        else:
                            print(f"  {account_llm}")
                    
                    # Transaction-level LLM
                    if result['llm_explanations'].get('transaction'):
                        transaction_llm = result['llm_explanations']['transaction']
                        print("\n⚡ Transaction Risk Analysis:")
                        if isinstance(transaction_llm, dict):
                            print(f"  Feature: {transaction_llm.get('feature_name', 'N/A')}")
                            print(f"  Value: {transaction_llm.get('feature_value', 'N/A')}")
                            print(f"  Explanation: {transaction_llm.get('reason', 'N/A')}")
                        else:
                            print(f"  {transaction_llm}")
                
                # Print full JSON response (optional, for debugging)
                print("\n" + "=" * 80)
                print("FULL JSON RESPONSE")
                print("=" * 80)
                print(json.dumps(result, indent=2))
                
            else:
                print(f"\n✗ Request failed with status {response.status_code}")
                try:
                    error_detail = response.json()
                    print("Error Details:")
                    print(json.dumps(error_detail, indent=2))
                except:
                    print(f"Error Text: {response.text}")
                    
    except httpx.TimeoutException:
        print("\n✗ Request timed out (>120s)")
        print("   This might happen if:")
        print("   - Account has many transactions (try reducing max_transactions)")
        print("   - Etherscan/Rarible API is slow")
    except Exception as e:
        print(f"\n✗ Unexpected error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()


async def main():
    """Run test cases for account detection"""
    
    print("\n" + "=" * 80)
    print("ACCOUNT-TASK DETECTION TEST SUITE")
    print("=" * 80)
    print("\nThis test validates the complete account detection flow:")
    print("  1. Fetch ERC721 & ERC1155 transactions from Etherscan")
    print("  2. Enrich with NFT pricing data from Rarible API")
    print("  3. Feature engineering (account + transaction level)")
    print("  4. Multi-task model prediction")
    print("  5. SHAP explanation (feature importance)")
    print("  6. LLM explanation (human-readable)")
    print("=" * 80)
    
    # Test cases
    test_cases = [
        {
            "name": "Test 1: Account with NFT transactions",
            "address": "0x693B725a375f599F0b6EfA0d910E749E1Bec1555",
            "max_txns": 10
        },
        {
            "name": "Test 3: New account (no transactions)",
            "address": "0xd9bd2ff54ad19dd27887d2e2fa7b60d003cddfaa",
            "max_txns": 10
        }
    ]
    
    # Get address from command line if provided
    if len(sys.argv) > 1:
        address = sys.argv[1]
        max_txns = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        print(f"\n🔍 Testing custom address: {address}")
        await test_account_detection(
            account_address=address,
            explain=True,
            explain_with_llm=True,
            max_transactions=max_txns
        )
    else:
        # Run default test cases
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n\n{'='*80}")
            print(f"[{test_case['name']}]")
            print("=" * 80)
            await test_account_detection(
                account_address=test_case['address'],
                explain=True,
                explain_with_llm=True,
                max_transactions=test_case['max_txns']
            )
            
            if i < len(test_cases):
                print("\n⏳ Waiting 3 seconds before next test...")
                await asyncio.sleep(3)
    
    print("\n" + "=" * 80)
    print("✓ All test cases completed!")



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠ Tests interrupted by user")
        sys.exit(1)

