"""
Health check and system status routes
"""

from fastapi import APIRouter, Depends
from app.auth import get_current_user, User

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """
    Public health check endpoint (no authentication required).

    Returns:
        System health status
    """
    return {
        "status": "healthy",
        "service": "utip-core-api",
        "version": "1.0.0",
        "theme": "Midnight Vulture"
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
