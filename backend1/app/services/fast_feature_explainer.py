"""
Fast Feature Explainer
Uses gradient-based feature importance instead of SHAP for faster explanations
"""
import numpy as np
import torch
from typing import Dict, Any, List
from app.services.model import MTL_MLP


class FastFeatureExplainer:
    """
    Fast gradient-based feature importance explainer.
    Much faster than SHAP (milliseconds vs seconds).
    """
    
    def __init__(self, model: MTL_MLP, device="cpu"):
        self.model = model
        self.device = device
        self.model.to(device)
        self.model.eval()
    
    def explain_prediction(self, features: np.ndarray, task_id: str, feature_names: List[str]) -> Dict[str, Any]:
        """
        Explain prediction using gradient-based feature importance.
        
        Args:
            features: numpy array shape (n_samples, n_features) or (n_features,)
            task_id: 'transaction' or 'account'
            feature_names: list of feature names
        
        Returns:
            dict with feature_importance (top 5) and raw importance scores
        """
        # Convert to tensor
        if isinstance(features, np.ndarray):
            X = torch.tensor(features, dtype=torch.float32, device=self.device, requires_grad=True)
        else:
            X = features.clone().detach().requires_grad_(True).to(self.device)
        
        # Handle 1D input
        if X.ndim == 1:
            X = X.unsqueeze(0)
        
        # Forward pass
        output = self.model(X, task_id=task_id)
        
        # Get prediction (logit before sigmoid)
        if output.ndim > 1:
            output = output.squeeze()
        
        # For single sample, we can use the output directly
        # For multiple samples, we'll use the first one or average
        if X.shape[0] > 1:
            # Use first sample for explanation
            target_output = output[0]
            target_X = X[0:1]
        else:
            target_output = output
            target_X = X
        
        # Backward pass to get gradients
        self.model.zero_grad()
        target_output.backward(retain_graph=True)
        
        # Get gradients w.r.t. input features
        gradients = target_X.grad
        
        # Calculate feature importance as absolute gradient values
        # Higher gradient = more important feature
        importance_scores = torch.abs(gradients).squeeze().cpu().detach().numpy()
        
        # If importance_scores is 1D, it's already correct
        if importance_scores.ndim == 0:
            importance_scores = np.array([importance_scores])
        
        # Normalize importance scores to sum to 1 (for interpretability)
        total_importance = np.sum(importance_scores)
        if total_importance > 0:
            normalized_importance = importance_scores / total_importance
        else:
            normalized_importance = importance_scores
        
        # Create feature importance list
        fi = []
        for name, imp_score, norm_imp, feat_val in zip(
            feature_names, 
            importance_scores, 
            normalized_importance,
            X[0].cpu().detach().numpy()
        ):
            fi.append({
                "feature_name": name,
                "importance_score": float(imp_score),
                "normalized_importance": float(norm_imp),
                "feature_value": float(feat_val)
            })
        
        # Sort by absolute importance and take top 5
        fi.sort(key=lambda x: abs(x["importance_score"]), reverse=True)
        top_5_fi = fi[:5]
        
        # Get prediction probability
        with torch.no_grad():
            prob = torch.sigmoid(target_output).item()
        
        return {
            "prediction_probability": prob,
            "prediction_logit": float(target_output.item()),
            "feature_importance": top_5_fi,
            "raw_importance_scores": importance_scores.tolist(),
            "normalized_importance_scores": normalized_importance.tolist(),
            "method": "gradient_based"
        }
    
    def explain_batch(self, features: np.ndarray, task_id: str, feature_names: List[str]) -> Dict[str, Any]:
        """
        Explain a batch of predictions (uses average importance across batch).
        """
        # Convert to tensor
        X = torch.tensor(features, dtype=torch.float32, device=self.device, requires_grad=True)
        
        if X.ndim == 1:
            X = X.unsqueeze(0)
        
        # Forward pass
        output = self.model(X, task_id=task_id)
        
        if output.ndim > 1:
            output = output.squeeze()
        
        # Calculate gradients for each sample
        importance_scores_list = []
        
        for i in range(X.shape[0]):
            self.model.zero_grad()
            sample_output = output[i] if output.ndim > 0 else output
            sample_X = X[i:i+1]
            
            sample_output.backward(retain_graph=True, create_graph=False)
            gradients = sample_X.grad
            importance_scores = torch.abs(gradients).squeeze().cpu().detach().numpy()
            
            if importance_scores.ndim == 0:
                importance_scores = np.array([importance_scores])
            
            importance_scores_list.append(importance_scores)
        
        # Average importance across batch
        avg_importance = np.mean(importance_scores_list, axis=0)
        
        # Normalize
        total_importance = np.sum(avg_importance)
        if total_importance > 0:
            normalized_importance = avg_importance / total_importance
        else:
            normalized_importance = avg_importance
        
        # Create feature importance list
        fi = []
        for name, imp_score, norm_imp in zip(feature_names, avg_importance, normalized_importance):
            fi.append({
                "feature_name": name,
                "importance_score": float(imp_score),
                "normalized_importance": float(norm_imp)
            })
        
        # Sort and take top 5
        fi.sort(key=lambda x: abs(x["importance_score"]), reverse=True)
        top_5_fi = fi[:5]
        
        # Get average prediction
        with torch.no_grad():
            probs = torch.sigmoid(output).cpu().numpy()
            avg_prob = float(np.mean(probs))
        
        return {
            "average_prediction_probability": avg_prob,
            "feature_importance": top_5_fi,
            "raw_importance_scores": avg_importance.tolist(),
            "normalized_importance_scores": normalized_importance.tolist(),
            "method": "gradient_based_batch"
        }

