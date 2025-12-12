"""
Main FastAPI Application
NFT Phishing Detection Backend - Merged from web3-scam-radar-be and Web3-Scamming-Attack-Detection
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.routers import detect as detect_router
from app.routers import account as account_router
from app.routers.detect_blacklist_router import router as detect_bl_router
from app.services.model_loader import load_model
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    debug=settings.api_debug
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests and responses"""
    start_time = time.time()
    
    # Log request
    logger.info(f"→ {request.method} {request.url.path} | Client: {request.client.host if request.client else 'unknown'}")
    
    try:
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log response
        logger.info(f"← {request.method} {request.url.path} | Status: {response.status_code} | Duration: {duration:.2f}s")
        
        return response
    except Exception as e:
        duration = time.time() - start_time
        logger.exception(f"✗ {request.method} {request.url.path} | Error after {duration:.2f}s: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal server error: {str(e)}"}
        )

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(detect_router.router)
app.include_router(account_router.router)
app.include_router(detect_bl_router)

@app.on_event("startup")
async def startup_event():
    """Load model at startup"""
    try:
        logger.info("Loading model at startup...")
        model, account_features, transaction_features = load_model()
        logger.info(f"✓ Model loaded successfully")
        logger.info(f"✓ Account features: {len(account_features)}")
        logger.info(f"✓ Transaction features: {len(transaction_features)}")
        logger.info("Backend ready!")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise

@app.get("/")
def root():
    """Root endpoint"""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "status": "ready"
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    try:
        from app.services.model_loader import get_model
        model = get_model()
        return {
            "status": "healthy",
            "model_loaded": model is not None
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }

