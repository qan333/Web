#!/usr/bin/env python3
"""
Startup script for the backend
"""
import uvicorn
import os
from app.main import app

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),  # Render sẽ inject PORT
        reload=True,
        log_level="info"
    )