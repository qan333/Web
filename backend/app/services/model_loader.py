"""
Model Loader
Loads MTL_MLP model at startup
"""
import os
import torch
import json
import numpy as np
from typing import Dict, Any, Tuple, List
from sklearn.preprocessing import StandardScaler
from app.services.model import MTL_MLP
from app.config import settings

# Global model instance
_model_instance = None
_account_feature_names = None
_transaction_feature_names = None
_account_scaler = None
_transaction_scaler = None
_training_statistics = None  # Store mean and std from training data

def load_training_statistics() -> dict:
    """
    Load training statistics (mean, std) from JSON file
    Returns: Dictionary with 'account' and 'transaction' statistics
    """
    global _training_statistics
    
    if _training_statistics is not None:
        return _training_statistics
    
    # Try to load from models directory
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    stats_path = os.path.join(BASE_DIR, 'models', 'training_statistics.json')
    
    # Try alternative paths
    if not os.path.exists(stats_path):
        stats_path = os.path.join(os.path.dirname(BASE_DIR), 'models', 'training_statistics.json')
    
    if os.path.exists(stats_path):
        try:
            with open(stats_path, 'r') as f:
                _training_statistics = json.load(f)
            print(f"✅ Loaded training statistics from: {stats_path}")
            return _training_statistics
        except Exception as e:
            print(f"⚠️  Failed to load training statistics: {e}")
    
    # Return None if not found
    print("⚠️  Training statistics file not found. Using fallback scaling.")
    return None

def load_model() -> Tuple[MTL_MLP, List[str], List[str]]:
    """
    Load model and feature names at startup
    Returns: (model, account_feature_names, transaction_feature_names)
    """
    global _model_instance, _account_feature_names, _transaction_feature_names
    
    if _model_instance is not None:
        return _model_instance, _account_feature_names, _transaction_feature_names
    
    # Load training statistics
    load_training_statistics()
    
    # Define paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    MODEL_DIR = os.path.join(BASE_DIR, settings.model_dir)
    FEATURES_DIR = os.path.join(BASE_DIR, settings.features_dir)
    
    # Load model
    MODEL_PATH = os.path.join(MODEL_DIR, 'MTL_MLP_best.pth')
    
    if not os.path.exists(MODEL_PATH):
        # Try relative path from backend folder
        MODEL_PATH = os.path.join(os.path.dirname(BASE_DIR), 'models', 'MTL_MLP_best.pth')
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
    
    # Initialize model with correct architecture
    model = MTL_MLP(
        input_dim=15,
        shared_dim=128,
        head_hidden_dim=64
    )
    
    # Load model weights robustly
    ckpt = torch.load(MODEL_PATH, map_location=torch.device('cpu'))
    # support checkpoints that wrap state dict
    if isinstance(ckpt, dict):
        if 'state_dict' in ckpt:
            state = ckpt['state_dict']
        elif 'model_state_dict' in ckpt:
            state = ckpt['model_state_dict']
        else:
            state = ckpt
    else:
        state = ckpt
    
    # strip module prefix if present
    new_state = {}
    for k, v in state.items():
        new_k = k.replace('module.', '') if k.startswith('module.') else k
        new_state[new_k] = v
    
    model.load_state_dict(new_state)
    model.eval()
    
    # Load feature lists
    account_features_path = os.path.join(FEATURES_DIR, "AccountLevel_top15_features.json")
    transaction_features_path = os.path.join(FEATURES_DIR, "TransactionLevel_top15_features.json")
    
    # Try alternative paths
    if not os.path.exists(account_features_path):
        account_features_path = os.path.join(os.path.dirname(BASE_DIR), 'features', 'AccountLevel_top15_features.json')
    if not os.path.exists(transaction_features_path):
        transaction_features_path = os.path.join(os.path.dirname(BASE_DIR), 'features', 'TransactionLevel_top15_features.json')
    
    if not os.path.exists(account_features_path) or not os.path.exists(transaction_features_path):
        raise FileNotFoundError(f"Feature importance files not found: {account_features_path}, {transaction_features_path}")
    
    with open(account_features_path, "r") as f:
        ACCOUNT_FEATURES = json.load(f)
    
    with open(transaction_features_path, "r") as f:
        TRANSACTION_FEATURES = json.load(f)
    
    def _feature_name_list(feature_json):
        # Accept either list of strings or list of dicts with 'feature' key
        if not feature_json:
            return []
        if isinstance(feature_json[0], str):
            return feature_json
        elif isinstance(feature_json[0], dict) and 'feature' in feature_json[0]:
            return [f['feature'] for f in feature_json]
        else:
            # fallback: convert items to str
            return [str(f) for f in feature_json]
    
    ACCOUNT_FEATURE_NAMES = _feature_name_list(ACCOUNT_FEATURES)
    TRANSACTION_FEATURE_NAMES = _feature_name_list(TRANSACTION_FEATURES)
    
    _model_instance = model
    _account_feature_names = ACCOUNT_FEATURE_NAMES
    _transaction_feature_names = TRANSACTION_FEATURE_NAMES
    
    return model, ACCOUNT_FEATURE_NAMES, TRANSACTION_FEATURE_NAMES

def get_model() -> MTL_MLP:
    """Get the loaded model instance"""
    if _model_instance is None:
        load_model()
    return _model_instance

def get_feature_names() -> Tuple[List[str], List[str]]:
    """Get feature names"""
    if _account_feature_names is None or _transaction_feature_names is None:
        load_model()
    return _account_feature_names, _transaction_feature_names

def get_scalers() -> Tuple[StandardScaler, StandardScaler]:
    """Get StandardScaler instances for account and transaction features"""
    global _account_scaler, _transaction_scaler
    
    if _account_scaler is None or _transaction_scaler is None:
        # Initialize scalers (will be fitted on-the-fly with reasonable defaults)
        # Since we don't have training statistics, we'll use a robust approach:
        # 1. Clip extreme values (outlier handling)
        # 2. Apply log transform for very large values
        # 3. Standard scale
        
        # Create scalers - they will be used with clipping and log transform
        _account_scaler = StandardScaler()
        _transaction_scaler = StandardScaler()
        
        # Note: In production, these should be fitted on training data
        # For now, we'll use a transform that handles extreme values
    
    return _account_scaler, _transaction_scaler

def scale_features(features: np.ndarray, task: str = 'account') -> np.ndarray:
    """
    Scale features using training statistics (mean, std) from training data
    
    Args:
        features: Raw feature array (1D or 2D)
        task: 'account' or 'transaction'
    
    Returns:
        Scaled features (same shape as input)
    """
    # Load training statistics if available
    stats = load_training_statistics()
    
    # Ensure we work with a copy
    features_processed = features.copy()
    
    # Handle 1D array (single sample)
    is_1d = features_processed.ndim == 1
    if is_1d:
        features_processed = features_processed.reshape(1, -1)
    
    n_samples = features_processed.shape[0]
    n_features = features_processed.shape[1]
    
    # Apply log transform for very large values (e.g., total_volume)
    # Only apply to positive values > 1e10 (same as training)
    large_mask = features_processed > 1e10
    if large_mask.any():
        features_processed[large_mask] = np.log1p(features_processed[large_mask])
    
    # Use training statistics if available
    if stats and task in stats:
        task_stats = stats[task]
        training_mean = np.array(task_stats['mean'])
        training_std = np.array(task_stats['std'])
        
        # Validate feature dimensions match
        if len(training_mean) != n_features:
            print(f"⚠️  Feature dimension mismatch: expected {len(training_mean)}, got {n_features}")
            print(f"   Using fallback scaling instead")
        else:
            # Use training statistics for standardization
            # Standardize: (x - mean) / std
            # This works even with 1 sample because we use training mean/std, not sample mean/std
            std_safe = np.where(training_std > 1e-8, training_std, 1.0)  # Avoid division by zero
            scaled = (features_processed - training_mean) / std_safe
            
            # Return to original shape
            if is_1d:
                scaled = scaled.flatten()
            
            return scaled
    
    # Fallback: Use sample-based scaling (only works with multiple samples)
    print(f"⚠️  No training statistics available for {task}. Using fallback scaling.")
    
    if n_samples == 1:
        # Single sample: cannot standardize (would zero out)
        # Just apply log transform and clipping
        features_scaled = features_processed.copy()
        features_scaled = np.clip(features_scaled, -5.0, 15.0)
        scaled = features_scaled
    else:
        # Multiple samples: can use proper standardization
        # Clip to reasonable range (percentile-based) for each feature
        for i in range(features_processed.shape[1]):
            col_data = features_processed[:, i]
            
            if col_data.max() > 0 and np.std(col_data) > 0:
                # Use robust clipping: clip to 3 standard deviations
                mean_val = np.mean(col_data)
                std_val = np.std(col_data)
                if std_val > 0:
                    lower = mean_val - 3 * std_val
                    upper = mean_val + 3 * std_val
                    features_processed[:, i] = np.clip(col_data, lower, upper)
        
        # Standardize (mean=0, std=1) - only works with multiple samples
        mean = np.mean(features_processed, axis=0)
        std = np.std(features_processed, axis=0)
        
        # Avoid division by zero
        std = np.where(std > 1e-8, std, 1.0)
        scaled = (features_processed - mean) / std
    
    # Return to original shape
    if is_1d:
        scaled = scaled.flatten()
    
    return scaled

