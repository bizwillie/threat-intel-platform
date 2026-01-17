"""
Keycloak JWT Authentication Middleware

Handles JWT validation, user context, and role-based access control.

Non-negotiable constraints:
- On-premises Keycloak
- OIDC protocol
- JWT Bearer tokens
- Role-based access control (analyst, admin, hunter)
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from typing import Optional, List
import httpx
import os
import logging

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

# Keycloak configuration from environment
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "utip")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "utip-api")

# JWT validation settings
ALGORITHM = "RS256"


class User:
    """User model from JWT claims"""

    def __init__(self, username: str, email: str, roles: List[str], user_id: str):
        self.username = username
        self.email = email
        self.roles = roles
        self.user_id = user_id

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles

    def __repr__(self):
        return f"User(username={self.username}, roles={self.roles})"


async def get_keycloak_public_key() -> str:
    """
    Fetch Keycloak public key for JWT verification.

    In production, this should be cached to avoid repeated requests.
    """
    try:
        url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            realm_info = response.json()
            return realm_info.get("public_key")
    except Exception as e:
        logger.error(f"Failed to fetch Keycloak public key: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable"
        )


def verify_token(token: str, public_key: str) -> dict:
    """
    Verify JWT token signature and extract claims.

    Args:
        token: JWT token string
        public_key: Keycloak realm public key

    Returns:
        Decoded token claims

    Raises:
        HTTPException: If token is invalid
    """
    try:
        # Add PEM headers if not present
        if not public_key.startswith("-----BEGIN"):
            public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

        # Decode and verify token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=KEYCLOAK_CLIENT_ID,
        )

        return payload

    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    FastAPI dependency to extract and validate current user from JWT.

    Usage:
        @app.get("/protected")
        async def protected_route(user: User = Depends(get_current_user)):
            return {"message": f"Hello {user.username}"}

    Args:
        credentials: HTTP Authorization header with Bearer token

    Returns:
        User object with username, email, roles

    Raises:
        HTTPException: If token is invalid or missing
    """
    token = credentials.credentials

    # Get Keycloak public key
    public_key = await get_keycloak_public_key()

    # Verify token
    payload = verify_token(token, public_key)

    # Extract user information from token claims
    username = payload.get("preferred_username")
    email = payload.get("email")
    user_id = payload.get("sub")

    # Extract roles from resource_access or realm_access
    roles = []

    # Check client-specific roles
    resource_access = payload.get("resource_access", {})
    client_roles = resource_access.get(KEYCLOAK_CLIENT_ID, {}).get("roles", [])
    roles.extend(client_roles)

    # Check realm roles
    realm_access = payload.get("realm_access", {})
    realm_roles = realm_access.get("roles", [])
    roles.extend(realm_roles)

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims",
        )

    return User(
        username=username,
        email=email or "",
        roles=list(set(roles)),  # Deduplicate roles
        user_id=user_id
    )


def require_role(required_role: str):
    """
    FastAPI dependency factory for role-based access control.

    Usage:
        @app.post("/admin/action")
        async def admin_action(user: User = Depends(require_role("admin"))):
            return {"message": "Admin action performed"}

    Args:
        required_role: Role name (analyst, admin, hunter)

    Returns:
        Dependency function that validates role
    """
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if not user.has_role(required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        return user

    return role_checker


# Convenience dependencies for specific roles
require_analyst = require_role("analyst")
require_admin = require_role("admin")
require_hunter = require_role("hunter")
