"""
UTIP Authentication Module

Keycloak OIDC/JWT authentication and authorization.
"""

from .keycloak import (
    get_current_user,
    require_role,
    verify_token,
)

__all__ = [
    "get_current_user",
    "require_role",
    "verify_token",
]
