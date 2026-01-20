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

import os
import time
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Import shared utilities
from app.shared.rate_limiter import limiter
from app.shared.logging_config import get_logger, get_security_logger

# Import routers
from app.routes import health_router, intel_router, vuln_router, layer_router, attribution_router, remediation_router

# Configure structured logging
logger = get_logger(__name__)
security_logger = get_security_logger()


# Maximum request body size (50MB for file uploads)
MAX_REQUEST_SIZE = int(os.environ.get("MAX_REQUEST_SIZE", 50 * 1024 * 1024))


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Validate incoming requests for security.

    Checks:
    - Request body size limits
    - Content-Type validation for POST/PUT/PATCH
    - Path traversal prevention
    """

    ALLOWED_CONTENT_TYPES = [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
        "text/xml",
    ]

    async def dispatch(self, request: Request, call_next):
        # Check content length for requests with body
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    if size > MAX_REQUEST_SIZE:
                        return JSONResponse(
                            status_code=413,
                            content={"detail": f"Request body too large. Maximum size: {MAX_REQUEST_SIZE} bytes"}
                        )
                except ValueError:
                    pass  # Invalid content-length, let FastAPI handle it

            # Validate content type (skip for multipart which has boundary)
            content_type = request.headers.get("content-type", "")
            if content_type and not any(ct in content_type for ct in self.ALLOWED_CONTENT_TYPES):
                # Allow requests without body (content-length 0)
                if content_length and int(content_length) > 0:
                    logger.warning(f"Rejected request with unsupported content-type: {content_type}")
                    return JSONResponse(
                        status_code=415,
                        content={"detail": f"Unsupported content type: {content_type}"}
                    )

        # Path traversal check
        if ".." in request.url.path or "%2e%2e" in request.url.path.lower():
            logger.warning(f"Path traversal attempt blocked: {request.url.path}")
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid path"}
            )

        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all HTTP requests with timing and correlation.

    Provides:
    - Request/response logging for debugging
    - Performance metrics (duration_ms)
    - Correlation IDs for distributed tracing
    """

    # Paths to exclude from logging (reduce noise)
    EXCLUDE_PATHS = {"/health", "/metrics", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        # Skip logging for excluded paths
        if request.url.path in self.EXCLUDE_PATHS:
            return await call_next(request)

        # Start timing
        start_time = time.perf_counter()

        # Get or generate request ID
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

        # Extract client info
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        try:
            response = await call_next(request)

            # Calculate duration
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Log the request
            logger.info(
                f"{request.method} {request.url.path} - {response.status_code}",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "ip_address": client_ip,
                    "user_agent": user_agent[:100] if user_agent else None  # Truncate long UAs
                }
            )

            return response

        except Exception as e:
            # Log errors
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"{request.method} {request.url.path} - Error: {str(e)}",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                    "ip_address": client_ip,
                    "error": str(e)
                }
            )
            raise


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.

    OWASP recommended headers for API security:
    - X-Content-Type-Options: Prevent MIME sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Legacy XSS protection (for older browsers)
    - Strict-Transport-Security: Force HTTPS
    - X-Request-ID: Request correlation for logging/debugging
    - Cache-Control: Prevent caching of sensitive data
    """

    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID for correlation
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

        # HSTS header (only in production with HTTPS)
        if os.environ.get("ENVIRONMENT") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy (disable unnecessary browser features)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


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

# Add middleware stack (order matters - first added = last executed)
# 1. Request validation (security checks)
app.add_middleware(RequestValidationMiddleware)

# 2. Request logging (performance + debugging)
app.add_middleware(RequestLoggingMiddleware)

# 3. Security headers (all responses)
app.add_middleware(SecurityHeadersMiddleware)

# Include routers
app.include_router(health_router)
app.include_router(intel_router)
app.include_router(vuln_router)
app.include_router(layer_router)
app.include_router(attribution_router)
app.include_router(remediation_router)

# CORS configuration
# Environment variable CORS_ORIGINS accepts comma-separated list of origins
# Default: http://localhost:4200 for local development
cors_origins_env = os.environ.get("CORS_ORIGINS", "http://localhost:4200")
cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
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
    logger.info(f"CORS origins configured: {cors_origins}")

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
