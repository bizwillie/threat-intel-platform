"""
Health check and system status routes

Provides:
- /health - Basic liveness probe
- /health/ready - Readiness probe with dependency checks
- /api/v1/me - Current user info
"""

import os
import asyncio
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends
import httpx

from app.auth import get_current_user, User
from app.shared.logging_config import get_logger

router = APIRouter(tags=["Health"])
logger = get_logger(__name__)

# Service version
VERSION = "1.0.0"


async def check_database() -> Dict[str, Any]:
    """Check database connectivity."""
    try:
        # Import here to avoid circular dependency
        from app.database import get_db, AsyncSession
        from sqlalchemy import text

        # Get a session and try a simple query
        async for db in get_db():
            result = await db.execute(text("SELECT 1"))
            result.fetchone()
            return {"status": "healthy", "latency_ms": 0}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


async def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        client = redis.from_url(redis_url)

        start = datetime.utcnow()
        await client.ping()
        latency = (datetime.utcnow() - start).total_seconds() * 1000

        await client.close()
        return {"status": "healthy", "latency_ms": round(latency, 2)}
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


async def check_keycloak() -> Dict[str, Any]:
    """Check Keycloak connectivity."""
    try:
        keycloak_url = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
        realm = os.environ.get("KEYCLOAK_REALM", "utip")

        async with httpx.AsyncClient(timeout=5.0) as client:
            start = datetime.utcnow()
            response = await client.get(f"{keycloak_url}/realms/{realm}")
            latency = (datetime.utcnow() - start).total_seconds() * 1000

            if response.status_code == 200:
                return {"status": "healthy", "latency_ms": round(latency, 2)}
            else:
                return {"status": "degraded", "status_code": response.status_code}
    except Exception as e:
        logger.error(f"Keycloak health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


@router.get("/health")
async def health_check():
    """
    Basic liveness probe (no authentication required).

    Use this for Kubernetes liveness probes.
    Only checks if the API process is running.

    Returns:
        System health status
    """
    return {
        "status": "healthy",
        "service": "utip-core-api",
        "version": VERSION,
        "theme": "Midnight Vulture",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/health/ready")
async def readiness_check():
    """
    Readiness probe with dependency checks.

    Use this for Kubernetes readiness probes.
    Checks all critical dependencies (DB, Redis, Keycloak).

    Returns:
        Detailed health status of all dependencies
    """
    # Run all health checks in parallel
    db_check, redis_check, keycloak_check = await asyncio.gather(
        check_database(),
        check_redis(),
        check_keycloak(),
        return_exceptions=True
    )

    # Handle any exceptions from gather
    if isinstance(db_check, Exception):
        db_check = {"status": "unhealthy", "error": str(db_check)}
    if isinstance(redis_check, Exception):
        redis_check = {"status": "unhealthy", "error": str(redis_check)}
    if isinstance(keycloak_check, Exception):
        keycloak_check = {"status": "unhealthy", "error": str(keycloak_check)}

    # Determine overall status
    dependencies = {
        "database": db_check,
        "redis": redis_check,
        "keycloak": keycloak_check
    }

    all_healthy = all(d.get("status") == "healthy" for d in dependencies.values())
    any_unhealthy = any(d.get("status") == "unhealthy" for d in dependencies.values())

    if all_healthy:
        overall_status = "healthy"
    elif any_unhealthy:
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return {
        "status": overall_status,
        "service": "utip-core-api",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dependencies": dependencies
    }


@router.get("/api/v1/me")
async def get_current_user_info(user: User = Depends(get_current_user)):
    """
    Get current authenticated user information.

    Requires valid JWT token.

    Returns:
        User information including username, email, and roles
    """
    return {
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "user_id": user.user_id
    }
