"""
UTIP Core API - "The Brain"

Main FastAPI application entrypoint.
Responsibilities:
- System state management
- Data persistence
- Correlation logic
- Layer generation
- Attribution orchestration
- Authentication & authorization
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="UTIP Core API",
    description="Unified Threat Intelligence Platform - Mission-Critical Cybersecurity Fusion",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],  # Frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Application startup event handler"""
    logger.info("🚀 UTIP Core API starting up...")
    logger.info("Theme: Midnight Vulture")
    logger.info("Classification: INTERNAL USE ONLY")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event handler"""
    logger.info("🛑 UTIP Core API shutting down...")

@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns:
        dict: Health status of the API
    """
    return {
        "status": "healthy",
        "service": "utip-core-api",
        "version": "1.0.0",
        "theme": "Midnight Vulture"
    }

@app.get("/")
async def root():
    """
    Root endpoint - API information.

    Returns:
        dict: API information and links
    """
    return {
        "name": "UTIP Core API",
        "description": "Unified Threat Intelligence Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }
