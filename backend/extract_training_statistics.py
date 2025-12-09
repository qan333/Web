"""
Extract Training Statistics from Training Notebook
==================================================

This script extracts mean and std statistics from training data
to be used for feature scaling during inference.

Based on training-mlt.ipynb notebook:
- Training data is scaled with StandardScaler
- Account features: X_train_addr_scaled
- Transaction features: X_train_txn_scaled

Usage:
    # Option 1: If you have the training data CSV files
    python extract_training_statistics.py --account_csv path/to/X_account_features_raw.csv --transaction_csv path/to/X_trans_features_raw.csv
    
    # Option 2: If you have the scaled training data (from notebook)
    python extract_training_statistics.py --account_scaled_csv path/to/X_train_addr_scaled.csv --transaction_scaled_csv path/to/X_train_txn_scaled.csv
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import argparse
from sklearn.preprocessing import StandardScaler
from pathlib import Path
from typing import List, Dict, Any

def extract_statistics_from_scaled_data(
    account_features_scaled: np.ndarray,
    transaction_features_scaled: np.ndarray,
    output_dir: str = "backend/models"
) -> dict:
    """
    Extract mean and std from ALREADY SCALED training data
    (This is a workaround - normally we'd extract from raw data)
    
    Note: If data is already scaled, mean should be ~0 and std should be ~1
    But we need the ORIGINAL mean and std that were used for scaling.
    
    This function assumes you have the RAW training data before scaling.
    """
    print("⚠️  WARNING: This function expects RAW (unscaled) training data!")
    print("   If you have scaled data, you need the original scaler statistics.")
    return None

def extract_statistics_from_raw_data(
    account_features_raw: np.ndarray,
    transaction_features_raw: np.ndarray,
    output_dir: str = "backend/models"
) -> dict:
    """
    Extract mean and std statistics from RAW training features
    (Before scaling, but after log transform if needed)
    
    This matches the training process in notebook:
    1. Load raw features
    2. Apply log transform for large values (> 1e10)
    3. Fit StandardScaler
    4. Extract mean and std
    """
    print("Extracting statistics from raw training data...")
    
    # Apply same preprocessing as in training (log transform for large values)
    # This matches the preprocessing in model_loader.py
    def preprocess_features(features):
        features_processed = features.copy().astype(np.float64)
        
        # Handle any remaining inf or NaN
        features_processed = np.nan_to_num(features_processed, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Apply log transform for very large values (> 1e10)
        # This matches the preprocessing in model_loader.py scale_features()
        large_mask = features_processed > 1e10
        if large_mask.any():
            n_large = large_mask.sum()
            print(f"   Applying log transform to {n_large} large values (>{1e10})")
            features_processed[large_mask] = np.log1p(features_processed[large_mask])
        
        return features_processed
    
    # Preprocess features (same as training)
    print("   Preprocessing account features...")
    account_features_processed = preprocess_features(account_features_raw)
    
    print("   Preprocessing transaction features...")
    transaction_features_processed = preprocess_features(transaction_features_raw)
    
    # Fit StandardScaler on processed features (same as training)
    print("   Fitting StandardScaler on account features...")
    account_scaler = StandardScaler()
    account_scaler.fit(account_features_processed)
    
    print("   Fitting StandardScaler on transaction features...")
    transaction_scaler = StandardScaler()
    transaction_scaler.fit(transaction_features_processed)
    
    # Extract statistics
    statistics = {
        'account': {
            'mean': account_scaler.mean_.tolist(),
            'std': account_scaler.scale_.tolist(),  # scale_ is std
            'n_features': len(account_scaler.mean_),
            'n_samples': account_features_raw.shape[0]
        },
        'transaction': {
            'mean': transaction_scaler.mean_.tolist(),
            'std': transaction_scaler.scale_.tolist(),
            'n_features': len(transaction_scaler.mean_),
            'n_samples': transaction_features_raw.shape[0]
        }
    }
    
    # Save to JSON file
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'training_statistics.json')
    
    with open(output_path, 'w') as f:
        json.dump(statistics, f, indent=2)
    
    print(f"\n✅ Training statistics saved to: {output_path}")
    print(f"   Account: {statistics['account']['n_features']} features, {statistics['account']['n_samples']} samples")
    print(f"   Transaction: {statistics['transaction']['n_features']} features, {statistics['transaction']['n_samples']} samples")
    print(f"\n   Account mean range: [{min(statistics['account']['mean']):.6f}, {max(statistics['account']['mean']):.6f}]")
    print(f"   Account std range: [{min(statistics['account']['std']):.6f}, {max(statistics['account']['std']):.6f}]")
    print(f"   Transaction mean range: [{min(statistics['transaction']['mean']):.6f}, {max(statistics['transaction']['mean']):.6f}]")
    print(f"   Transaction std range: [{min(statistics['transaction']['std']):.6f}, {max(statistics['transaction']['std']):.6f}]")
    
    return statistics

def load_top15_feature_names(task: str = 'account') -> List[str]:
    """
    Load top 15 feature names from feature importance JSON files
    
    Args:
        task: 'account' or 'transaction'
    
    Returns:
        List of feature names in order of importance
    """
    # Get the directory where this script is located (backend/)
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # Features directory is in backend/features
    features_dir = os.path.join(SCRIPT_DIR, 'features')
    
    if task == 'account':
        feature_file = os.path.join(features_dir, 'AccountLevel_top15_features.json')
    else:
        feature_file = os.path.join(features_dir, 'TransactionLevel_top15_features.json')
    
    # Try alternative paths if not found
    if not os.path.exists(feature_file):
        # Try: backend/features (relative to script)
        alt_path1 = os.path.join(SCRIPT_DIR, '..', 'features', 
                                 'AccountLevel_top15_features.json' if task == 'account' 
                                 else 'TransactionLevel_top15_features.json')
        alt_path1 = os.path.normpath(alt_path1)
        if os.path.exists(alt_path1):
            feature_file = alt_path1
        else:
            # Try: root/features
            ROOT_DIR = os.path.dirname(SCRIPT_DIR)
            alt_path2 = os.path.join(ROOT_DIR, 'features',
                                     'AccountLevel_top15_features.json' if task == 'account' 
                                     else 'TransactionLevel_top15_features.json')
            if os.path.exists(alt_path2):
                feature_file = alt_path2
    
    if not os.path.exists(feature_file):
        raise FileNotFoundError(f"Feature importance file not found: {feature_file}\n"
                              f"   Tried: {features_dir}\n"
                              f"   Please ensure the file exists in backend/features/")
    
    with open(feature_file, 'r') as f:
        feature_data = json.load(f)
    
    # Extract feature names (handle both dict and string formats)
    feature_names = []
    for item in feature_data:
        if isinstance(item, dict):
            feature_names.append(item.get('feature', ''))
        elif isinstance(item, str):
            feature_names.append(item)
    
    print(f"   Loaded {len(feature_names)} top features for {task} task")
    return feature_names

def load_features_from_csv(csv_path: str, drop_label: bool = True, select_top15: bool = False, task: str = 'account') -> np.ndarray:
    """
    Load features from CSV file and optionally select top 15 features
    
    Args:
        csv_path: Path to CSV file
        drop_label: Whether to drop label/address columns
        select_top15: If True, select only top 15 features based on feature importance
        task: 'account' or 'transaction' (used when select_top15=True)
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    
    print(f"Loading features from: {csv_path}")
    df = pd.read_csv(csv_path)
    
    print(f"   CSV shape: {df.shape}")
    print(f"   Columns: {list(df.columns[:10])}..." if len(df.columns) > 10 else f"   Columns: {list(df.columns)}")
    
    # Drop non-feature columns
    columns_to_drop = []
    if drop_label and 'label' in df.columns:
        columns_to_drop.append('label')
    if drop_label and 'address' in df.columns:
        columns_to_drop.append('address')
    
    if columns_to_drop:
        df = df.drop(columns=columns_to_drop, axis=1)
        print(f"   Dropped columns: {columns_to_drop}")
    
    # If select_top15, map columns to top 15 features
    if select_top15 and df.shape[1] > 15:
        print(f"   Selecting top 15 features from {df.shape[1]} total features...")
        top15_names = load_top15_feature_names(task=task)
        
        # Special handling: Calculate missing features if needed
        # For transaction task, calculate 'high_gas' from 'gas_used' if missing
        if task == 'transaction' and 'high_gas' in top15_names and 'high_gas' not in df.columns:
            if 'gas_used' in df.columns:
                print(f"   Calculating 'high_gas' from 'gas_used' (75th percentile threshold)...")
                # Calculate high_gas: ratio of transactions above 75th percentile
                gas_used_values = df['gas_used'].values
                if len(gas_used_values) > 0 and np.max(gas_used_values) > 0:
                    gas_75th = np.percentile(gas_used_values[gas_used_values > 0], 75) if np.any(gas_used_values > 0) else 0
                    high_gas_count = np.sum(gas_used_values > gas_75th)
                    high_gas_ratio = high_gas_count / len(gas_used_values) if len(gas_used_values) > 0 else 0
                    # For each row, calculate if it's high gas (this is a per-sample calculation)
                    # But for training statistics, we need aggregate, so use the ratio
                    df['high_gas'] = (gas_used_values > gas_75th).astype(float)
                    print(f"   ✅ Calculated 'high_gas' (75th percentile: {gas_75th:.2f}, ratio: {high_gas_ratio:.4f})")
                else:
                    df['high_gas'] = 0.0
                    print(f"   ⚠️  No valid gas_used values, setting high_gas to 0")
            else:
                print(f"   ⚠️  Cannot calculate 'high_gas': 'gas_used' column not found")
        
        # Try to match column names (case-insensitive)
        selected_cols = []
        missing_features = []
        for feat_name in top15_names:
            matched = False
            for col in df.columns:
                # Try exact match
                if col == feat_name:
                    selected_cols.append(col)
                    matched = True
                    break
                # Try case-insensitive match
                elif col.lower() == feat_name.lower():
                    selected_cols.append(col)
                    matched = True
                    break
                # Try partial match (e.g., "addr_out_txn" matches "out_txn")
                elif feat_name.lower() in col.lower() or col.lower() in feat_name.lower():
                    selected_cols.append(col)
                    matched = True
                    break
            
            if not matched:
                missing_features.append(feat_name)
                print(f"   ⚠️  Could not find column for feature: {feat_name}")
        
        if len(selected_cols) < 15:
            print(f"   ⚠️  Warning: Only found {len(selected_cols)} matching columns out of 15 required")
            if missing_features:
                print(f"   Missing features: {missing_features}")
            print(f"   Available columns: {list(df.columns)}")
            print(f"   Top 15 feature names: {top15_names}")
            # Fallback: take first 15 columns
            print(f"   ⚠️  Falling back to first 15 columns (may not match feature order!)")
            selected_cols = list(df.columns[:15])
        
        # Select and reorder columns to match top15_names order
        # Create ordered list matching top15_names
        ordered_cols = []
        for feat_name in top15_names:
            # Find matching column
            for col in selected_cols:
                if (col == feat_name or 
                    col.lower() == feat_name.lower() or
                    feat_name.lower() in col.lower() or 
                    col.lower() in feat_name.lower()):
                    if col not in ordered_cols:
                        ordered_cols.append(col)
                        break
        
        # Add any remaining columns if we don't have 15 yet
        for col in selected_cols:
            if col not in ordered_cols and len(ordered_cols) < 15:
                ordered_cols.append(col)
        
        if len(ordered_cols) == 15:
            df_selected = df[ordered_cols]
            print(f"   ✅ Selected and ordered {len(df_selected.columns)} features to match top15 order")
        else:
            df_selected = df[selected_cols[:15]]
            print(f"   ✅ Selected {len(df_selected.columns)} features (order may not match)")
        
        df = df_selected
    
    # Convert to numpy array
    features = df.values
    
    # Convert to float and handle any non-numeric values
    try:
        features = features.astype(np.float64)
    except ValueError as e:
        print(f"   ⚠️  Warning: Some non-numeric values found. Attempting to convert...")
        # Try to convert, replacing non-numeric with NaN then 0
        features = pd.DataFrame(features).apply(pd.to_numeric, errors='coerce').fillna(0).values.astype(np.float64)
    
    # Handle inf and NaN
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    
    print(f"   ✅ Loaded {features.shape[0]} samples, {features.shape[1]} features")
    print(f"   Feature value range: [{features.min():.6f}, {features.max():.6f}]")
    
    return features

def main():
    parser = argparse.ArgumentParser(description='Extract training statistics for feature scaling')
    parser.add_argument('--account_csv', type=str, help='Path to account features CSV (raw, before scaling)')
    parser.add_argument('--transaction_csv', type=str, help='Path to transaction features CSV (raw, before scaling)')
    parser.add_argument('--output_dir', type=str, default='backend/models', help='Output directory for statistics file')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("Extract Training Statistics for Feature Scaling")
    print("=" * 80)
    
    if args.account_csv and args.transaction_csv:
        # Load from CSV files and select top 15 features
        print("\n📊 Loading and selecting top 15 features...")
        account_features = load_features_from_csv(args.account_csv, select_top15=True, task='account')
        transaction_features = load_features_from_csv(args.transaction_csv, select_top15=True, task='transaction')
        
        # Extract statistics
        statistics = extract_statistics_from_raw_data(
            account_features,
            transaction_features,
            output_dir=args.output_dir
        )
        
        print("\n✅ Success! Training statistics extracted and saved.")
        print(f"   File: {os.path.join(args.output_dir, 'training_statistics.json')}")
        print("\n   Next step: Update model_loader.py to use these statistics")
        
    else:
        print("\n⚠️  No CSV files provided!")
        print("\nUsage:")
        print("  python extract_training_statistics.py \\")
        print("    --account_csv path/to/X_account_features_raw.csv \\")
        print("    --transaction_csv path/to/X_trans_features_raw.csv")
        print("\nOr if you have the training data from notebook:")
        print("  1. Export X_train_addr (before scaling) to CSV")
        print("  2. Export X_train_txn (before scaling) to CSV")
        print("  3. Run this script with those CSV files")
        print("\nAlternatively, you can add this code to your training notebook:")
        print("  # After fitting scalers:")
        print("  statistics = {")
        print("      'account': {'mean': scaler_addr.mean_.tolist(), 'std': scaler_addr.scale_.tolist()},")
        print("      'transaction': {'mean': scaler_txn.mean_.tolist(), 'std': scaler_txn.scale_.tolist()}")
        print("  }")
        print("  with open('training_statistics.json', 'w') as f:")
        print("      json.dump(statistics, f, indent=2)")

if __name__ == "__main__":
    main()
