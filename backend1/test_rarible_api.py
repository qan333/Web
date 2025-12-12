"""
Test script for Rarible API
Tests the collection statistics API and NFT data enrichment
"""
import asyncio
import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.rarible_client import (
    collection_statistics,
    enrich_transaction_with_nft_data,
    _extract_eth_value,
    rarible_get
)
from app.config import settings


async def test_extract_eth_value():
    """Test the _extract_eth_value helper function"""
    print("\n=== Testing _extract_eth_value ===")
    
    # Test case 1: Normal ETH value
    price_list_1 = [
        {"currency": "USD", "value": 2635},
        {"currency": "ETH", "value": 1.0}
    ]
    result_1 = _extract_eth_value(price_list_1)
    print(f"Test 1 - ETH value: {result_1} (expected: 1.0)")
    assert result_1 == 1.0, f"Expected 1.0, got {result_1}"
    
    # Test case 2: Only USD (should convert)
    price_list_2 = [
        {"currency": "USD", "value": 2000}
    ]
    result_2 = _extract_eth_value(price_list_2)
    print(f"Test 2 - USD converted: {result_2} (expected: ~1.0)")
    assert result_2 > 0, "Should convert USD to ETH"
    
    # Test case 3: Empty list
    result_3 = _extract_eth_value([])
    print(f"Test 3 - Empty list: {result_3} (expected: 0.0)")
    assert result_3 == 0.0, f"Expected 0.0, got {result_3}"
    
    # Test case 4: None
    result_4 = _extract_eth_value(None)
    print(f"Test 4 - None: {result_4} (expected: 0.0)")
    assert result_4 == 0.0, f"Expected 0.0, got {result_4}"
    
    print("[OK] All _extract_eth_value tests passed!")


async def test_collection_statistics():
    """Test the collection_statistics API call"""
    print("\n=== Testing collection_statistics API ===")
    
    # Test with a known NFT collection (Bored Ape Yacht Club)
    # Contract: 0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D
    test_collection_id = "ETHEREUM:0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D"
    
    try:
        print(f"Testing with collection: {test_collection_id}")
        print(f"API Key: {settings.rarible_api_key[:10]}..." if settings.rarible_api_key else "No API key")
        
        stats = await collection_statistics(test_collection_id)
        
        print(f"\n[OK] API call successful!")
        print(f"Response keys: {list(stats.keys())}")
        
        # Check expected fields
        expected_fields = ["listed", "items", "owners", "highestSale", "floorPrice", "marketCap", "volume"]
        for field in expected_fields:
            if field in stats:
                value = stats[field]
                if isinstance(value, list):
                    print(f"  {field}: {value}")
                else:
                    print(f"  {field}: {value}")
            else:
                print(f"  [WARN] {field}: MISSING")
        
        # Test extraction
        floor_price = _extract_eth_value(stats.get("floorPrice", []))
        market_cap = _extract_eth_value(stats.get("marketCap", []))
        volume = _extract_eth_value(stats.get("volume", []))
        
        print(f"\nExtracted values:")
        print(f"  Floor Price (ETH): {floor_price}")
        print(f"  Market Cap (ETH): {market_cap}")
        print(f"  Volume (ETH): {volume}")
        print(f"  Owners: {stats.get('owners', 'N/A')}")
        print(f"  Items: {stats.get('items', 'N/A')}")
        
    except Exception as e:
        print(f"\n[ERROR] Error calling API: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


async def test_enrich_transaction():
    """Test enriching a transaction with NFT data"""
    print("\n=== Testing enrich_transaction_with_nft_data ===")
    
    # Create a sample transaction with BAYC contract
    test_transaction = {
        "from_address": "0x1234567890123456789012345678901234567890",
        "to_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "value": 0,
        "gasPrice": 20000000000,
        "gasUsed": 100000,
        "timestamp": 1640995200,
        "function_call": ["transferFrom"],
        "transaction_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "blockNumber": 15000000,
        "contract_address": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",  # BAYC
        "token_value": 0,
        "token_decimal": 0,
        "nft_floor_price": 0,
        "nft_average_price": 0,
        "nft_total_volume": 0,
        "nft_total_sales": 0,
        "nft_num_owners": 0,
        "nft_market_cap": 0,
        "nft_7day_volume": 0,
        "nft_7day_sales": 0,
        "nft_7day_avg_price": 0,
        "tx_type": "erc721",
    }
    
    try:
        print(f"Testing with contract: {test_transaction['contract_address']}")
        
        enriched = await enrich_transaction_with_nft_data(test_transaction.copy())
        
        print(f"\n[OK] Enrichment successful!")
        print(f"\nNFT fields after enrichment:")
        print(f"  nft_num_owners: {enriched.get('nft_num_owners', 0)}")
        print(f"  nft_total_sales: {enriched.get('nft_total_sales', 0)}")
        print(f"  nft_floor_price: {enriched.get('nft_floor_price', 0)}")
        print(f"  nft_average_price: {enriched.get('nft_average_price', 0)}")
        print(f"  nft_total_volume: {enriched.get('nft_total_volume', 0)}")
        print(f"  nft_market_cap: {enriched.get('nft_market_cap', 0)}")
        print(f"  nft_7day_volume: {enriched.get('nft_7day_volume', 0)}")
        print(f"  nft_7day_sales: {enriched.get('nft_7day_sales', 0)}")
        print(f"  nft_7day_avg_price: {enriched.get('nft_7day_avg_price', 0)}")
        
        # Check if values were populated
        has_data = any([
            enriched.get('nft_num_owners', 0) > 0,
            enriched.get('nft_total_sales', 0) > 0,
            enriched.get('nft_floor_price', 0) > 0,
            enriched.get('nft_market_cap', 0) > 0,
            enriched.get('nft_total_volume', 0) > 0,
        ])
        
        if has_data:
            print("\n[OK] NFT data was successfully populated!")
        else:
            print("\n[WARN] Warning: No NFT data was populated (may be normal for new/unknown contracts)")
        
    except Exception as e:
        print(f"\n[ERROR] Error enriching transaction: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


async def test_invalid_collection():
    """Test with an invalid collection address"""
    print("\n=== Testing with invalid collection ===")
    
    test_collection_id = "ETHEREUM:0x0000000000000000000000000000000000000000"
    
    try:
        stats = await collection_statistics(test_collection_id)
        print(f"Response: {stats}")
        if stats:
            print("[WARN] Got response for invalid collection (may be expected)")
        else:
            print("[OK] No response for invalid collection (expected)")
    except Exception as e:
        print(f"✓ Error as expected for invalid collection: {type(e).__name__}")


async def test_no_contract_address():
    """Test enriching transaction with no contract address"""
    print("\n=== Testing transaction with no contract address ===")
    
    test_transaction = {
        "from_address": "0x1234567890123456789012345678901234567890",
        "to_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "value": 1000000000000000000,
        "contract_address": "",  # Empty contract address
    }
    
    try:
        enriched = await enrich_transaction_with_nft_data(test_transaction.copy())
        
        # Should return unchanged transaction
        assert enriched == test_transaction, "Transaction should be unchanged when no contract address"
        print("[OK] Transaction correctly left unchanged when no contract address")
        
    except Exception as e:
        print(f"[ERROR] Unexpected error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


async def main():
    """Run all tests"""
    print("=" * 60)
    print("Rarible API Test Suite")
    print("=" * 60)
    print(f"Base URL: https://api.rarible.org/v0.1")
    print(f"API Key configured: {'Yes' if settings.rarible_api_key else 'No'}")
    
    try:
        # Run tests
        await test_extract_eth_value()
        await test_collection_statistics()
        await test_enrich_transaction()
        await test_invalid_collection()
        await test_no_contract_address()
        
        print("\n" + "=" * 60)
        print("[OK] All tests completed!")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n\n[WARN] Tests interrupted by user")
    except Exception as e:
        print(f"\n\n[ERROR] Test suite failed: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

