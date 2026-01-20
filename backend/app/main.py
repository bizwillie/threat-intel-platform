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

SECURITY: Rate limiting enabled via slowapi to prevent:
- Brute force attacks
- DoS via resource exhaustion
- API abuse
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import logging

# Import shared utilities (centralized rate limiter)
from app.shared.rate_limiter import limiter

# Import routers
from app.routes import health_router, intel_router, vuln_router, layer_router, attribution_router, remediation_router

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

# Attach rate limiter to app state and add exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include routers
app.include_router(health_router)
app.include_router(intel_router)
app.include_router(vuln_router)
app.include_router(layer_router)
app.include_router(attribution_router)
app.include_router(remediation_router)

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
