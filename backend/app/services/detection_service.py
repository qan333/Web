"""
Detection Service
Main service that orchestrates the detection flow:
1. Fetch data from Etherscan and Rarible APIs
2. Feature engineering
3. Model prediction
4. Gradient-based feature importance explanation
5. LLM explanation
"""
import torch
import numpy as np
import logging
import time
from typing import Dict, Any, Optional, List
from app.services.etherscan_client import get_account_transactions
from app.services.rarible_client import enrich_transactions_with_nft_data, enrich_transaction_with_nft_data
from app.services.feature_engineer import extract_account_level_features, extract_transaction_level_features
from app.services.model_loader import get_model, get_feature_names, scale_features
from app.services.shap_explainer import SHAPExplainer
from app.services.fast_feature_explainer import FastFeatureExplainer
from app.services.llm_explainer import LLMExplainer

logger = logging.getLogger(__name__)

# Optimization: Limit to max 10 transactions for Rarible enrichment and feature extraction
# This significantly reduces API calls and processing time for accounts with many NFT transactions
MAX_TRANSACTIONS_FOR_FEATURES = 10


class DetectionService:
    def __init__(self):
        logger.info("Initializing DetectionService components...")
        self.model = get_model()
        self.account_feature_names, self.transaction_feature_names = get_feature_names()
        logger.info(f"Loaded {len(self.account_feature_names)} account features, {len(self.transaction_feature_names)} transaction features")
        
        # Use fast gradient-based explainer instead of SHAP for speed
        self.feature_explainer = FastFeatureExplainer(self.model, device="cpu")
        logger.info("Fast feature explainer initialized (gradient-based)")
        
        # Keep SHAP as fallback option (not used by default)
        self.shap_explainer = None  # SHAPExplainer(self.model, device="cpu")
        
        try:
            self.llm_explainer = LLMExplainer()
            logger.info("LLM explainer initialized successfully")
        except Exception as e:
            logger.warning(f"LLM explainer not available: {e}")
            self.llm_explainer = None
    
    async def detect_transaction(
        self,
        transaction_data: Dict[str, Any],
        explain: bool = False,
        explain_with_llm: bool = False
    ) -> Dict[str, Any]:
        """
        Detect phishing/scam activity for a single transaction
        
        Args:
            transaction_data: Transaction data with from_address, to_address, value, etc.
            explain: Include gradient-based feature importance explanations
            explain_with_llm: Include LLM explanations
        
        Returns:
            Detection results for transaction-level only
        """
        start_time = time.time()
        logger.info("⏱️ [TIMING] Starting transaction detection")
        logger.debug(f"[DEBUG] Transaction data before enrichment: gasPrice={transaction_data.get('gasPrice')}, gasUsed={transaction_data.get('gasUsed')}, value={transaction_data.get('value')}, functions={transaction_data.get('function_call')}")
        
        # Enrich transaction with NFT data
        rarible_start = time.time()
        enriched_transaction = await enrich_transaction_with_nft_data(transaction_data)
        rarible_time = time.time() - rarible_start
        logger.info(f"⏱️ [TIMING] Rarible API enrichment: {rarible_time:.2f}s")
        logger.debug(f"[DEBUG] Transaction data after enrichment: gasPrice={enriched_transaction.get('gasPrice')}, gasUsed={enriched_transaction.get('gasUsed')}, value={enriched_transaction.get('value')}, functions={enriched_transaction.get('function_call')}")
        
        # Extract transaction-level features only
        feature_start = time.time()
        transaction_features = extract_transaction_level_features([enriched_transaction])
        feature_time = time.time() - feature_start
        logger.info(f"⏱️ [TIMING] Feature extraction: {feature_time:.3f}s")
        logger.debug(f"[DEBUG] Raw transaction features: {transaction_features}")
        logger.debug(f"[DEBUG] Feature shape: {transaction_features.shape}, dtype: {transaction_features.dtype}")
        
        # Detailed feature logging for debugging
        # Handle both 1D and 2D arrays
        if transaction_features.size > 0:
            if transaction_features.ndim == 1:
                # 1D array - single transaction
                feature_values_str = ", ".join([f"{self.transaction_feature_names[i]}={transaction_features[i]:.2f}" 
                                                for i in range(min(len(self.transaction_feature_names), len(transaction_features)))])
            else:
                # 2D array - multiple transactions
                feature_values_str = ", ".join([f"{self.transaction_feature_names[i]}={transaction_features[0][i]:.2f}" 
                                                for i in range(min(len(self.transaction_feature_names), len(transaction_features[0])))])
            logger.info(f"[DEBUG] Feature values: {feature_values_str}")
        
        # Scale features before prediction
        scale_start = time.time()
        transaction_features_scaled = scale_features(transaction_features, task='transaction')
        scale_time = time.time() - scale_start
        logger.info(f"⏱️ [TIMING] Feature scaling: {scale_time:.3f}s")
        logger.debug(f"[DEBUG] Scaled transaction features: {transaction_features_scaled}")
        logger.debug(f"[DEBUG] Scaled feature shape: {transaction_features_scaled.shape}, dtype: {transaction_features_scaled.dtype}")
        logger.debug(f"[DEBUG] Scaled feature range: [{transaction_features_scaled.min():.6f}, {transaction_features_scaled.max():.6f}]")
        
        # Make prediction using transaction-level model only
        model_start = time.time()
        with torch.no_grad():
            transaction_features_tensor = torch.tensor(transaction_features_scaled, dtype=torch.float32).unsqueeze(0)
            logger.debug(f"[DEBUG] Model input tensor shape: {transaction_features_tensor.shape}, dtype: {transaction_features_tensor.dtype}")
            logger.debug(f"[DEBUG] Model input tensor range: [{transaction_features_tensor.min():.6f}, {transaction_features_tensor.max():.6f}]")
            transaction_logit = self.model(transaction_features_tensor, task_id='transaction').squeeze()
            transaction_prob = float(torch.sigmoid(transaction_logit).item())
        logger.info(f"[MODEL][TRANSACTION] logit={float(transaction_logit):.6f}, prob={transaction_prob:.6f}")
        logger.info(f"[DEBUG] Transaction hash: {transaction_data.get('transaction_hash', 'N/A')}")
        logger.info(f"[DEBUG] From: {transaction_data.get('from_address', 'N/A')}, To: {transaction_data.get('to_address', 'N/A')}")
        logger.info(f"[DEBUG] GasPrice: {transaction_data.get('gasPrice', 0)}, GasUsed: {transaction_data.get('gasUsed', 0)}, Value: {transaction_data.get('value', 0)}")
        model_time = time.time() - model_start
        logger.info(f"⏱️ [TIMING] Model inference: {model_time:.3f}s")
        
        response = {
            "account_address": transaction_data.get("from_address", ""),
            "to_address": transaction_data.get("to_address", ""),
            "account_scam_probability": None,  # Not available for new accounts
            "transaction_scam_probability": transaction_prob,
            "transactions_count": 1,
            "detection_mode": "transaction_only"  # Indicate this is transaction-only detection
        }
        
        # Generate feature importance explanations if requested
        if explain or explain_with_llm:
            explain_start = time.time()
            transaction_explanation = self.feature_explainer.explain_prediction(
                transaction_features_scaled.reshape(1, -1),
                'transaction',
                self.transaction_feature_names
            )
            explain_time = time.time() - explain_start
            logger.info(f"⏱️ [TIMING] Gradient-based explanation: {explain_time:.3f}s")
            
            # Convert to SHAP-like format for compatibility
            # Map importance_score to shap_value for LLM explainer compatibility
            feature_importance_mapped = []
            for feat in transaction_explanation.get("feature_importance", []):
                feature_importance_mapped.append({
                    "feature_name": feat["feature_name"],
                    "shap_value": feat["importance_score"],  # Use importance_score as shap_value
                    "feature_value": feat["feature_value"]
                })
            
            shap_like_explanation = {
                "expected_value": transaction_explanation.get("prediction_probability", 0.0),
                "feature_importance": feature_importance_mapped,
                "raw_shap_values": transaction_explanation.get("raw_importance_scores", []),
                "method": "gradient_based"
            }
            
            response["explanations"] = {
                "account": None,  # No account-level explanation
                "transaction": shap_like_explanation
            }
            
            # Generate LLM explanations if requested
            if explain_with_llm and self.llm_explainer:
                try:
                    gemini_start = time.time()
                    # Use mapped feature_importance with shap_value field
                    transaction_llm_explanation = await self.llm_explainer.explain_top_features(
                        transaction_prob,
                        "transaction",
                        shap_like_explanation["feature_importance"],  # Use mapped version with shap_value
                        max_words=100
                    )
                    gemini_time = time.time() - gemini_start
                    logger.info(f"⏱️ [TIMING] Gemini API call: {gemini_time:.2f}s")
                    
                    # LLM explanation is now a dict with feature_name, feature_value, reason
                    response["llm_explanations"] = {
                        "account": None,
                        "transaction": transaction_llm_explanation
                    }
                except Exception as e:
                    logger.error(f"⏱️ [TIMING] Gemini API failed after {time.time() - gemini_start:.2f}s: {str(e)}")
                    response["llm_explanations"] = {
                        "account": None,
                        "transaction": {
                            "feature_name": "Unknown",
                            "feature_value": "0",
                            "reason": f"Failed to generate LLM explanation: {str(e)}"
                        }
                    }
        
        total_time = time.time() - start_time
        logger.info(f"⏱️ [TIMING] Total transaction detection: {total_time:.2f}s")
        return response

    async def detect_account(
        self,
        account_address: str,
        explain: bool = False,
        explain_with_llm: bool = False,
        max_transactions: int = 1000
    ) -> Dict[str, Any]:
        """
        Main detection function for an account address
        
        Flow:
        1. Fetch transactions from Etherscan (ERC20, ERC721, ERC1155)
        2. Enrich with NFT data from Rarible
        3. Extract account-level features only
        4. Make account prediction only
        5. Generate gradient-based feature importance explanations (if requested)
        6. Generate LLM explanations (if requested)
        """
        start_time = time.time()
        logger.info("⏱️ [TIMING] Starting account detection")
        
        # Step 1: Fetch transactions from Etherscan
        etherscan_start = time.time()
        all_transactions = await get_account_transactions(account_address, max_txns=max_transactions)
        etherscan_time = time.time() - etherscan_start
        logger.info(f"⏱️ [TIMING] Etherscan API ({len(all_transactions)} transactions): {etherscan_time:.2f}s")
        
        if not all_transactions:
            total_time = time.time() - start_time
            logger.info(f"⏱️ [TIMING] Total account detection (no data): {total_time:.2f}s")
            # Return response indicating no data available
            return {
                "account_address": account_address,
                "account_scam_probability": None,  # Not available
                "transactions_count": 0,
                "detection_mode": "no_data",  # Indicate no data available
                "message": "No transactions found for this address."
            }
        
        # Step 1.5: Transactions are already limited to max 10 per type (ERC20, ERC721, ERC1155)
        # from get_account_transactions, so we use all of them for enrichment
        transactions_for_features = all_transactions
        logger.info(f"⏱️ [OPTIMIZATION] Using {len(transactions_for_features)} transactions for enrichment (max 10 ERC20 + max 10 ERC721 + max 10 ERC1155)")
        
        # Step 2: Enrich with NFT data from Rarible (only for limited transactions)
        rarible_start = time.time()
        enriched_transactions = await enrich_transactions_with_nft_data(transactions_for_features)
        rarible_time = time.time() - rarible_start
        logger.info(f"⏱️ [TIMING] Rarible API enrichment ({len(enriched_transactions)} transactions): {rarible_time:.2f}s")
        
        # Step 3: Extract account-level features only
        # Use enriched transactions for account features (NFT data is needed for some account features)
        feature_start = time.time()
        account_features = extract_account_level_features(account_address, enriched_transactions)
        feature_time = time.time() - feature_start
        logger.info(f"⏱️ [TIMING] Feature extraction: {feature_time:.3f}s")
        
        # Step 4: Scale features before prediction (required for model to work correctly)
        scale_start = time.time()
        account_features_scaled = scale_features(account_features, task='account')
        scale_time = time.time() - scale_start
        logger.info(f"⏱️ [TIMING] Feature scaling: {scale_time:.3f}s")
        
        # Debug: Log feature ranges before and after scaling
        logger.info(f"[DEBUG] Account features (raw): min={account_features.min():.6f}, max={account_features.max():.6f}, mean={account_features.mean():.6f}")
        logger.info(f"[DEBUG] Account features (scaled): min={account_features_scaled.min():.6f}, max={account_features_scaled.max():.6f}, mean={account_features_scaled.mean():.6f}")
        
        # Step 5: Make account prediction only
        model_start = time.time()
        with torch.no_grad():
            account_features_tensor = torch.tensor(account_features_scaled, dtype=torch.float32).unsqueeze(0)
            
            account_logit = self.model(account_features_tensor, task_id='account').squeeze()
            
            account_prob = float(torch.sigmoid(account_logit).item())
        logger.info(
            "[MODEL][ACCOUNT] logit=%.6f, prob=%.6f",
            float(account_logit),
            account_prob,
        )
        model_time = time.time() - model_start
        logger.info(f"⏱️ [TIMING] Model inference (account): {model_time:.3f}s")
        
        # Build response
        response = {
            "account_address": account_address,
            "account_scam_probability": account_prob,
            "transactions_count": len(all_transactions),  # Total transactions fetched
            "transactions_used_for_features": len(enriched_transactions)  # Transactions actually used for feature extraction
        }
        
        # Step 6: Generate feature importance explanations if requested
        if explain or explain_with_llm:
            explain_start = time.time()
            account_explanation = self.feature_explainer.explain_prediction(
                account_features_scaled.reshape(1, -1),
                'account',
                self.account_feature_names
            )
            explain_time = time.time() - explain_start
            logger.info(f"⏱️ [TIMING] Gradient-based explanations (account): {explain_time:.3f}s")
            
            # Convert to SHAP-like format for compatibility
            # Map importance_score to shap_value for LLM explainer compatibility
            account_feature_importance_mapped = []
            for feat in account_explanation.get("feature_importance", []):
                account_feature_importance_mapped.append({
                    "feature_name": feat["feature_name"],
                    "shap_value": feat["importance_score"],  # Use importance_score as shap_value
                    "feature_value": feat["feature_value"]
                })
            
            account_shap_like = {
                "expected_value": account_explanation.get("prediction_probability", 0.0),
                "feature_importance": account_feature_importance_mapped,
                "raw_shap_values": account_explanation.get("raw_importance_scores", []),
                "method": "gradient_based"
            }
            
            account_explanation = account_shap_like
            
            response["explanations"] = {
                "account": account_explanation
            }
            
            # Step 7: Generate LLM explanations if requested
            if explain_with_llm and self.llm_explainer:
                try:
                    gemini_start = time.time()
                    # Use mapped feature_importance with shap_value field
                    account_llm_explanation = await self.llm_explainer.explain_top_features(
                        account_prob,
                        "account",
                        account_shap_like["feature_importance"],  # Use mapped version with shap_value
                        max_words=100
                    )
                    account_gemini_time = time.time() - gemini_start
                    logger.info(f"⏱️ [TIMING] Gemini API (account): {account_gemini_time:.2f}s")
                    
                    # LLM explanations are now dicts with feature_name, feature_value, reason
                    response["llm_explanations"] = {
                        "account": account_llm_explanation
                    }
                except Exception as e:
                    logger.error(f"⏱️ [TIMING] Gemini API failed after {time.time() - gemini_start:.2f}s: {str(e)}")
                    response["llm_explanations"] = {
                        "account": {
                            "feature_name": "Unknown",
                            "feature_value": "0",
                            "reason": f"Failed to generate LLM explanation: {str(e)}"
                        }
                    }
        
        total_time = time.time() - start_time
        logger.info(f"⏱️ [TIMING] Total account detection: {total_time:.2f}s")
        return response

