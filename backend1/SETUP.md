# Setup Instructions

## Prerequisites

1. Python 3.8 or higher
2. Model file: `MTL_MLP_best.pth`

## Installation Steps

### 1. Copy Model File

Copy the trained model from `Web3-Scamming-Attack-Detection/Deploy/api/models/MTL_MLP_best.pth` to `backend/models/MTL_MLP_best.pth`:

```bash
# Windows
copy "Web3-Scamming-Attack-Detection\Deploy\api\models\MTL_MLP_best.pth" "backend\models\MTL_MLP_best.pth"

# Linux/Mac
cp "Web3-Scamming-Attack-Detection/Deploy/api/models/MTL_MLP_best.pth" "backend/models/MTL_MLP_best.pth"
```

### 2. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Configure Environment

Copy `.env.example` to `.env` (if not already exists):

```bash
# Windows
copy .env.example .env

# Linux/Mac
cp .env.example .env
```

The `.env` file already has the correct API keys configured:
- Etherscan: `ZJYVMX6ET1YKH7SPUPTQAU4H85FQPX8AJI`
- Rarible: `462992df-60b3-4b11-bed8-8a7e56cb9bd4`
- Gemini: `AIzaSyBILR9C86SFHWS0bbdIW1dLAribVpeGWHg`

### 4. Verify File Structure

Make sure you have:
```
backend/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── routers/
│   │   └── detect.py
│   └── services/
│       ├── etherscan_client.py
│       ├── rarible_client.py
│       ├── feature_engineer.py
│       ├── model.py
│       ├── model_loader.py
│       ├── shap_explainer.py
│       ├── llm_explainer.py
│       └── detection_service.py
├── models/
│   └── MTL_MLP_best.pth  ← Make sure this file exists!
├── features/
│   ├── AccountLevel_top15_features.json  ← Already created
│   └── TransactionLevel_top15_features.json  ← Already created
├── requirements.txt
└── run.py
```

### 5. Run the Backend

```bash
# Option 1: Using run.py
python run.py

# Option 2: Using uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The model will be loaded automatically at startup. You should see:
```
INFO: Loading model at startup...
INFO: ✓ Model loaded successfully
INFO: ✓ Account features: 15
INFO: ✓ Transaction features: 15
INFO: Backend ready!
```

### 6. Test the API

```bash
# Health check
curl http://localhost:8000/health

# Detect endpoint (without explanations)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"account_address": "0x..."}'

# Detect endpoint (with SHAP and LLM explanations)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "account_address": "0x...",
    "explain": true,
    "explain_with_llm": true
  }'
```

## Troubleshooting

### Model file not found
If you see `FileNotFoundError: Model file not found`, make sure:
1. The model file `MTL_MLP_best.pth` exists in `backend/models/`
2. Or update `MODEL_DIR` in `.env` to point to the correct directory

### Feature files not found
If you see `FileNotFoundError: Feature importance files not found`, make sure:
1. `AccountLevel_top15_features.json` exists in `backend/features/`
2. `TransactionLevel_top15_features.json` exists in `backend/features/`
3. Or update `FEATURES_DIR` in `.env` to point to the correct directory

### LLM explanation not working
If LLM explanations fail:
1. Check that `GEMINI_API_KEY` is set correctly in `.env`
2. Check your internet connection (Gemini API requires network access)
3. The API will still work without LLM explanations - only SHAP will be affected

## API Endpoints

- `GET /` - Root endpoint with API info
- `GET /health` - Health check
- `POST /detect` - Main detection endpoint

See `README.md` for detailed API documentation.

