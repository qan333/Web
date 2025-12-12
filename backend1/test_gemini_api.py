"""
Test script for Gemini API using the same code as LLMExplainer
"""
import google.generativeai as genai
import json
import re
import os
from typing import Dict, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def translate_feature_name(name: str) -> str:
    """Translate technical feature names to human-readable descriptions"""
    translations = {
        "avg_gas_price": "average transaction fee",
        "activity_duration_days": "account age in days",
        "std_time_between_txns": "irregularity in transaction timing",
        "total_volume": "total amount transferred",
        "inNeighborNum": "number of unique senders",
        "total_txn": "total number of transactions",
        "in_out_ratio": "ratio of incoming to outgoing transactions",
        "total_value_in": "total amount received",
        "outNeighborNum": "number of unique recipients",
        "avg_gas_used": "average transaction complexity",
        "giftinTxn_ratio": "proportion of token transfers",
        "miningTxnNum": "number of mining transactions",
        "avg_value_out": "average amount sent",
        "turnover_ratio": "frequency of fund movements",
        "out_txn": "number of outgoing transactions",
        "gas_price": "transaction fee",
        "gas_used": "transaction complexity",
        "value": "transaction amount",
        "num_functions": "number of contract interactions",
        "has_suspicious_func": "presence of suspicious functions",
        "nft_num_owners": "number of NFT owners",
        "nft_total_sales": "total NFT sales volume",
        "token_value": "token transfer value",
        "nft_total_volume": "total NFT trading volume",
        "is_mint": "is a new token creation",
        "high_gas": "high transaction fee",
        "nft_average_price": "average NFT price",
        "nft_floor_price": "minimum NFT price",
        "nft_market_cap": "total NFT market value",
        "is_zero_value": "zero-value transaction"
    }
    return translations.get(name, name)

def format_features_for_prompt(features: List[Dict]) -> str:
    """Format feature importance data for the prompt"""
    formatted = []
    for f in features:
        feature_name = translate_feature_name(f["feature_name"])
        impact = "increasing risk" if f["shap_value"] > 0 else "decreasing risk"
        formatted.append(f"- {feature_name} (value={f['feature_value']:.2f}): {impact}, importance={abs(f['shap_value']):.4f}")
    return "\n".join(formatted)

def test_gemini_explanation(prediction_prob: float, task_type: str, top_features: List[Dict]):
    """
    Test Gemini API with the same code as LLMExplainer
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY not found in environment variables")
        return
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.0-flash')
    
    risk_level = "HIGH" if prediction_prob > 0.7 else ("MEDIUM" if prediction_prob > 0.4 else "LOW")
    
    # Get top 3 features only for shorter response
    top_3_features = top_features[:3]
    
    prompt = f"""Analyze Web3 {task_type} risk. Return ONLY valid JSON, no other text.

Risk: {prediction_prob:.1%} ({risk_level})
Top features:
{format_features_for_prompt(top_3_features)}

Return JSON:
{{
  "summary": "One sentence risk summary (max 15 words)",
  "main_risk": "Top risk factor (max 10 words)",
  "recommendation": "Action advice (max 10 words)"
}}"""

    print("=" * 80)
    print("TESTING GEMINI API")
    print("=" * 80)
    print(f"\nModel: gemini-2.0-flash")
    print(f"Task Type: {task_type}")
    print(f"Prediction Probability: {prediction_prob:.1%} ({risk_level})")
    print(f"\nPrompt:\n{prompt}\n")
    print("=" * 80)
    
    try:
        print("\nCalling Gemini API...")
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.3,
                "max_output_tokens": 150,
            }
        )
        
        explanation_text = response.text.strip()
        print(f"\nRaw Response:\n{explanation_text}\n")
        
        # Try to extract JSON from response
        # Remove markdown code blocks if present
        explanation_text = re.sub(r'```json\s*', '', explanation_text)
        explanation_text = re.sub(r'```\s*', '', explanation_text)
        explanation_text = explanation_text.strip()
        
        print(f"Cleaned Response:\n{explanation_text}\n")
        
        try:
            # Try to parse as JSON
            json_data = json.loads(explanation_text)
            print("✓ Successfully parsed JSON!")
            print(f"\nParsed JSON:\n{json.dumps(json_data, indent=2)}")
            
            # Format as readable string (same as LLMExplainer)
            summary = json_data.get('summary', '')
            main_risk = json_data.get('main_risk', '')
            recommendation = json_data.get('recommendation', '')
            
            final_explanation = f"{summary} Main risk: {main_risk}. {recommendation}"
            print(f"\nFinal Explanation (as returned by LLMExplainer):\n{final_explanation}")
            
        except json.JSONDecodeError as e:
            print(f"✗ JSON Parse Error: {e}")
            print("Response is not valid JSON, using text directly...")
            words = explanation_text.split()
            if len(words) > 50:
                explanation_text = " ".join(words[:50]) + "..."
            print(f"\nTruncated Explanation:\n{explanation_text}")
        
    except Exception as e:
        print(f"✗ Error calling Gemini API: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback (same as LLMExplainer)
        top_feature_name = translate_feature_name(top_features[0]['feature_name'])
        risk_desc = "high risk" if top_features[0]['shap_value'] > 0 else "low risk"
        fallback = f"{risk_level} risk ({prediction_prob:.1%}). {top_feature_name} indicates {risk_desc}."
        print(f"\nFallback Explanation:\n{fallback}")

if __name__ == "__main__":
    # Test with sample data
    print("\n" + "=" * 80)
    print("TEST 1: Transaction Risk (HIGH)")
    print("=" * 80)
    test_gemini_explanation(
        prediction_prob=1.0,
        task_type="transaction",
        top_features=[
            {"feature_name": "has_suspicious_func", "shap_value": 0.5, "feature_value": 1.0},
            {"feature_name": "gas_price", "shap_value": 0.3, "feature_value": 1000000},
            {"feature_name": "is_zero_value", "shap_value": 0.2, "feature_value": 1.0},
        ]
    )
    
    print("\n\n" + "=" * 80)
    print("TEST 2: Account Risk (MEDIUM)")
    print("=" * 80)
    test_gemini_explanation(
        prediction_prob=0.6,
        task_type="account",
        top_features=[
            {"feature_name": "activity_duration_days", "shap_value": -0.2, "feature_value": 5.0},
            {"feature_name": "total_txn", "shap_value": 0.15, "feature_value": 10.0},
            {"feature_name": "avg_gas_price", "shap_value": 0.1, "feature_value": 50000},
        ]
    )
    
    print("\n\n" + "=" * 80)
    print("TEST 3: Low Risk")
    print("=" * 80)
    test_gemini_explanation(
        prediction_prob=0.2,
        task_type="transaction",
        top_features=[
            {"feature_name": "activity_duration_days", "shap_value": -0.3, "feature_value": 365.0},
            {"feature_name": "total_txn", "shap_value": -0.2, "feature_value": 100.0},
            {"feature_name": "avg_gas_price", "shap_value": -0.1, "feature_value": 20000},
        ]
    )
    
    print("\n" + "=" * 80)
    print("TESTING COMPLETE")
    print("=" * 80)

