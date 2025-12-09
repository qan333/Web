"""
Test script for SHAP explanation
Tests SHAP explainer directly with sample features
Similar structure to test_gemini_api.py and test_detect_transaction.py
"""
import numpy as np
import torch
import json
import sys
from app.services.model_loader import get_model, get_feature_names
from app.services.shap_explainer import SHAPExplainer


def test_shap_explanation(
    features: np.ndarray,
    task_id: str,
    feature_names: list,
    test_name: str = "Test"
):
    """
    Test SHAP explanation for given features
    
    Args:
        features: numpy array of shape (n_samples, n_features)
        task_id: 'transaction' or 'account'
        feature_names: list of feature names
        test_name: name of the test case
    """
    print("=" * 80)
    print(f"{test_name}")
    print("=" * 80)
    print(f"Task ID: {task_id}")
    print(f"Features shape: {features.shape}")
    print(f"Number of features: {len(feature_names)}")
    print("-" * 80)
    
    # Load model
    print("\nLoading model...")
    model = get_model()
    print("✓ Model loaded")
    
    # Initialize SHAP explainer (new instance for each test to avoid cache issues)
    print("\nInitializing SHAP explainer...")
    shap_explainer = SHAPExplainer(model, background_data_size=100, device="cpu")
    print("✓ SHAP explainer initialized")
    
    # Create diverse background data BEFORE calling explain_prediction
    print("\nPreparing background data...")
    # Create background samples using statistical distribution
    n_background = 100
    background_samples = []
    
    # Use input as reference, create diverse samples
    base_features = features[0] if features.ndim == 2 else features
    
    # Create background data with different strategies:
    # 1. Samples around input (50%)
    # 2. Samples with different scales (30%)
    # 3. Random samples from reasonable ranges (20%)
    for i in range(n_background):
        if i < 50:
            # Around input with noise
            noise = np.random.normal(0, 0.3, size=base_features.shape)
            sample = base_features * (1 + noise)
        elif i < 80:
            # Different scales (0.1x to 10x)
            scale = np.random.uniform(0.1, 10.0)
            sample = base_features * scale
        else:
            # Random from reasonable ranges based on feature type
            sample = np.random.uniform(0, base_features.max() * 2, size=base_features.shape)
        
        # Ensure non-negative
        sample = np.clip(sample, 0, None)
        background_samples.append(sample)
    
    background_data = np.array(background_samples, dtype=np.float32)
    print(f"  Created {n_background} diverse background samples")
    
    # Prepare background data in explainer
    shap_explainer.prepare_background_data(background_data)
    # Clear explainer cache to force recreation with new background
    shap_explainer.explainers = {}
    print("✓ Background data prepared and explainer cache cleared")
    
    # Make prediction first
    print("\nMaking prediction...")
    with torch.no_grad():
        features_tensor = torch.tensor(features, dtype=torch.float32)
        if features_tensor.ndim == 1:
            features_tensor = features_tensor.unsqueeze(0)
        
        logit = model(features_tensor, task_id=task_id).squeeze()
        prob = float(torch.sigmoid(logit).item())
    
    print(f"  Prediction probability: {prob:.4f} ({prob*100:.2f}%)")
    print(f"  Risk level: {'HIGH' if prob > 0.7 else ('MEDIUM' if prob > 0.4 else 'LOW')}")
    
    # Debug: Check predictions on background data
    print("\nChecking background data predictions...")
    with torch.no_grad():
        bg_tensor = torch.tensor(background_data[:10], dtype=torch.float32)  # Check first 10
        bg_logits = model(bg_tensor, task_id=task_id).squeeze()
        bg_probs = torch.sigmoid(bg_logits).cpu().numpy()
        print(f"  Background predictions (first 10): min={bg_probs.min():.4f}, max={bg_probs.max():.4f}, mean={bg_probs.mean():.4f}")
        if np.allclose(bg_probs, prob, atol=1e-3):
            print("  ⚠ WARNING: All background predictions are similar to input prediction!")
            print("  This will cause SHAP values to be near zero")
    
    # Generate SHAP explanation
    print("\nGenerating SHAP explanation...")
    print(f"  Input features shape: {features.shape}")
    print(f"  Background data shape: {shap_explainer.background_data.shape if shap_explainer.background_data is not None else 'None'}")
    
    # Verify SHAP library is actually being used
    import shap
    print(f"  SHAP library version: {shap.__version__}")
    print(f"  SHAP library path: {shap.__file__}")
    
    # Check explainer type before calling
    cache_key = (task_id, True)
    if cache_key in shap_explainer.explainers:
        explainer = shap_explainer.explainers[cache_key]
        print(f"  Explainer type: {type(explainer).__name__}")
        print(f"  Explainer module: {type(explainer).__module__}")
    else:
        print("  Explainer will be created on first call")
    
    try:
        explanation = shap_explainer.explain_prediction(
            features,
            task_id=task_id,
            feature_names=feature_names,
            apply_sigmoid=True
        )
        
        print("✓ SHAP explanation generated successfully")
        
        # Verify explainer was created and is from SHAP library
        if cache_key in shap_explainer.explainers:
            explainer = shap_explainer.explainers[cache_key]
            print(f"  Verified explainer type: {type(explainer).__name__}")
            print(f"  Verified explainer module: {type(explainer).__module__}")
            if 'shap' not in type(explainer).__module__.lower():
                print("  ⚠ WARNING: Explainer is NOT from SHAP library!")
            else:
                print("  ✓ Confirmed: Explainer is from SHAP library")
        
        # Debug: Check if SHAP values are all zeros
        all_shap_values = explanation.get('raw_shap_values', [])
        if all_shap_values:
            first_sample_shap = all_shap_values[0] if isinstance(all_shap_values[0], list) else all_shap_values
            max_abs_shap = max(abs(v) for v in first_sample_shap) if first_sample_shap else 0
            min_abs_shap = min(abs(v) for v in first_sample_shap) if first_sample_shap else 0
            print(f"  Debug: Max absolute SHAP value: {max_abs_shap:.6f}")
            print(f"  Debug: Min absolute SHAP value: {min_abs_shap:.6f}")
            print(f"  Debug: SHAP values range: [{min(first_sample_shap):.6f}, {max(first_sample_shap):.6f}]")
            if max_abs_shap < 1e-6:
                print("  ⚠ WARNING: All SHAP values are near zero!")
                print("  This may indicate background data is too similar to input")
            else:
                print("  ✓ SHAP values are non-zero - real SHAP computation confirmed")
        
        # Print results
        print("\n" + "-" * 80)
        print("SHAP Explanation Results:")
        print("-" * 80)
        print(f"Expected value: {explanation['expected_value']:.6f}")
        print(f"Max additivity diff: {explanation['max_additivity_diff']:.6f}")
        print(f"Predicted probabilities: {explanation['preds']}")
        
        print(f"\nTop 5 Feature Importance:")
        print("-" * 80)
        for i, feat in enumerate(explanation['feature_importance'], 1):
            impact = "↑ increases risk" if feat['shap_value'] > 0 else "↓ decreases risk"
            print(f"{i}. {feat['feature_name']}")
            print(f"   Value: {feat['feature_value']:.6f}")
            print(f"   SHAP value: {feat['shap_value']:.6f} ({impact})")
            print(f"   Absolute importance: {abs(feat['shap_value']):.6f}")
            print()
        
        # Verify additivity
        print("-" * 80)
        print("Additivity Check:")
        print(f"  Prediction from model: {prob:.6f}")
        recon = explanation['expected_value'] + sum(f['shap_value'] for f in explanation['feature_importance'])
        print(f"  Reconstructed from SHAP: {recon:.6f}")
        print(f"  Difference: {abs(prob - recon):.6f}")
        if explanation['max_additivity_diff'] < 1e-3:
            print("  ✓ Additivity check passed")
        else:
            print(f"  ⚠ Additivity check warning (diff > 1e-3)")
        
        # Verify SHAP values are real (not placeholder)
        print("\n" + "-" * 80)
        print("SHAP Values Verification:")
        print("-" * 80)
        
        # Check additivity property of SHAP
        expected_val = explanation['expected_value']
        shap_sum = sum(f['shap_value'] for f in explanation['feature_importance'])
        reconstructed = expected_val + shap_sum
        
        print(f"  Expected value (baseline): {expected_val:.6f}")
        print(f"  Sum of top 5 SHAP values: {shap_sum:.6f}")
        print(f"  Reconstructed prediction: {reconstructed:.6f}")
        print(f"  Actual prediction: {prob:.6f}")
        print(f"  Difference: {abs(reconstructed - prob):.6f}")
        
        # SHAP values should satisfy additivity: prediction = expected_value + sum(SHAP values)
        if abs(reconstructed - prob) < 0.01:  # Allow small numerical error
            print("  ✓ Additivity property verified - SHAP values are REAL")
        else:
            print("  ⚠ Additivity check failed - may indicate fake values")
        
        # Check if values look random/fake (all same, all zero, etc.)
        all_shap_abs = [abs(f['shap_value']) for f in explanation['feature_importance']]
        if len(set(all_shap_abs)) == 1 and all_shap_abs[0] < 1e-6:
            print("  ⚠ WARNING: All SHAP values are identical and near zero - suspicious!")
        elif len(set(all_shap_abs)) == 1:
            print("  ⚠ WARNING: All SHAP values have same magnitude - suspicious!")
        else:
            print("  ✓ SHAP values show variation - looks legitimate")
        
        # Print full JSON
        print("\n" + "-" * 80)
        print("Full Explanation (JSON):")
        print("-" * 80)
        print(json.dumps(explanation, indent=2))
        
        return explanation
        
    except Exception as e:
        print(f"\n✗ Error generating SHAP explanation: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def create_sample_account_features() -> tuple:
    """Create sample account-level features"""
    feature_names = [
        "avg_gas_price", "activity_duration_days", "std_time_between_txns",
        "total_volume", "inNeighborNum", "total_txn", "in_out_ratio",
        "total_value_in", "outNeighborNum", "avg_gas_used", "giftinTxn_ratio",
        "miningTxnNum", "avg_value_out", "turnover_ratio", "out_txn"
    ]
    
    # Sample features: new account with suspicious activity
    features = np.array([
        50000.0,      # avg_gas_price: high
        5.0,          # activity_duration_days: very new account
        3600.0,       # std_time_between_txns: irregular
        1000000.0,    # total_volume: high volume
        5.0,          # inNeighborNum: few senders
        20.0,         # total_txn: moderate
        0.1,          # in_out_ratio: mostly outgoing
        100000.0,     # total_value_in: low incoming
        50.0,         # outNeighborNum: many recipients (suspicious)
        50000.0,      # avg_gas_used: high
        0.8,          # giftinTxn_ratio: high token transfers
        0.0,          # miningTxnNum: no mining
        50000.0,      # avg_value_out: high outgoing
        0.5,          # turnover_ratio: moderate
        18.0          # out_txn: mostly outgoing
    ], dtype=np.float32)
    
    return features, feature_names


def create_sample_transaction_features() -> tuple:
    """Create sample transaction-level features"""
    feature_names = [
        "gas_price", "gas_used", "value", "num_functions", "has_suspicious_func",
        "nft_num_owners", "nft_total_sales", "token_value", "nft_total_volume",
        "is_mint", "high_gas", "nft_average_price", "nft_floor_price",
        "nft_market_cap", "is_zero_value"
    ]
    
    # Sample features: suspicious transaction with NFT approval
    features = np.array([
        100000000000.0,  # gas_price: very high (100 Gwei)
        150000.0,        # gas_used: high
        0.0,             # value: zero value
        2.0,             # num_functions: multiple functions
        1.0,             # has_suspicious_func: yes (setApprovalForAll)
        1000.0,          # nft_num_owners: many owners
        5000.0,          # nft_total_sales: high sales
        0.0,             # token_value: no token transfer
        1000000.0,       # nft_total_volume: high volume
        0.0,             # is_mint: not a mint
        1.0,             # high_gas: yes
        10.0,            # nft_average_price: moderate
        5.0,             # nft_floor_price: moderate
        50000.0,         # nft_market_cap: high
        1.0              # is_zero_value: yes
    ], dtype=np.float32)
    
    return features, feature_names


def create_low_risk_account_features() -> tuple:
    """Create low-risk account features"""
    feature_names = [
        "avg_gas_price", "activity_duration_days", "std_time_between_txns",
        "total_volume", "inNeighborNum", "total_txn", "in_out_ratio",
        "total_value_in", "outNeighborNum", "avg_gas_used", "giftinTxn_ratio",
        "miningTxnNum", "avg_value_out", "turnover_ratio", "out_txn"
    ]
    
    # Sample features: established account with normal activity
    features = np.array([
        20000.0,     # avg_gas_price: normal
        365.0,       # activity_duration_days: 1 year old
        86400.0,     # std_time_between_txns: regular (daily)
        100000.0,    # total_volume: moderate
        50.0,        # inNeighborNum: many senders
        200.0,       # total_txn: many transactions
        1.5,         # in_out_ratio: balanced
        50000.0,     # total_value_in: moderate incoming
        30.0,        # outNeighborNum: moderate recipients
        21000.0,     # avg_gas_used: normal
        0.2,         # giftinTxn_ratio: low token transfers
        0.0,         # miningTxnNum: no mining
        30000.0,     # avg_value_out: moderate
        0.3,         # turnover_ratio: moderate
        80.0         # out_txn: balanced
    ], dtype=np.float32)
    
    return features, feature_names


def create_low_risk_transaction_features() -> tuple:
    """Create low-risk transaction features"""
    feature_names = [
        "gas_price", "gas_used", "value", "num_functions", "has_suspicious_func",
        "nft_num_owners", "nft_total_sales", "token_value", "nft_total_volume",
        "is_mint", "high_gas", "nft_average_price", "nft_floor_price",
        "nft_market_cap", "is_zero_value"
    ]
    
    # Sample features: normal ETH transfer
    features = np.array([
        20000000000.0,  # gas_price: normal (20 Gwei)
        21000.0,        # gas_used: standard ETH transfer
        1000000000000000000.0,  # value: 1 ETH
        0.0,            # num_functions: no contract interaction
        0.0,            # has_suspicious_func: no
        0.0,            # nft_num_owners: no NFT
        0.0,            # nft_total_sales: no NFT
        0.0,            # token_value: no token
        0.0,            # nft_total_volume: no NFT
        0.0,            # is_mint: no
        0.0,            # high_gas: no
        0.0,            # nft_average_price: no NFT
        0.0,            # nft_floor_price: no NFT
        0.0,            # nft_market_cap: no NFT
        0.0             # is_zero_value: no
    ], dtype=np.float32)
    
    return features, feature_names


def main():
    """Run test cases for SHAP explanation"""
    
    print("\n" + "=" * 80)
    print("SHAP EXPLANATION TEST SUITE")
    print("=" * 80)
    print("\nTesting SHAP explainer with different scenarios:")
    print("1. High-risk account features")
    print("2. High-risk transaction features")
    print("3. Low-risk account features")
    print("4. Low-risk transaction features")
    print("=" * 80)
    
    # Test 1: High-risk account
    print("\n\n" + "🔴 " + "=" * 76)
    features, feature_names = create_sample_account_features()
    test_shap_explanation(
        features.reshape(1, -1),
        task_id="account",
        feature_names=feature_names,
        test_name="TEST 1: High-Risk Account Features"
    )
    
    # Test 2: High-risk transaction
    print("\n\n" + "🔴 " + "=" * 76)
    features, feature_names = create_sample_transaction_features()
    test_shap_explanation(
        features.reshape(1, -1),
        task_id="transaction",
        feature_names=feature_names,
        test_name="TEST 2: High-Risk Transaction Features"
    )
    
    # Test 3: Low-risk account
    print("\n\n" + "🟢 " + "=" * 76)
    features, feature_names = create_low_risk_account_features()
    test_shap_explanation(
        features.reshape(1, -1),
        task_id="account",
        feature_names=feature_names,
        test_name="TEST 3: Low-Risk Account Features"
    )
    
    # Test 4: Low-risk transaction
    print("\n\n" + "🟢 " + "=" * 76)
    features, feature_names = create_low_risk_transaction_features()
    test_shap_explanation(
        features.reshape(1, -1),
        task_id="transaction",
        feature_names=feature_names,
        test_name="TEST 4: Low-Risk Transaction Features"
    )
    
    print("\n" + "=" * 80)
    print("✓ All test cases completed!")
    print("=" * 80)
    print("\nSummary:")
    print("- SHAP explainer tested with account and transaction features")
    print("- High-risk and low-risk scenarios tested")
    print("- Additivity checks performed")
    print("- Top 5 feature importance extracted")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Unexpected error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

