"""
Shared utilities module for UTIP Core API.

This module contains shared utilities that are used across multiple routes and services.
"""

from app.shared.rate_limiter import limiter, get_remote_address
from app.shared.features import features, FeatureFlags

__all__ = ["limiter", "get_remote_address", "features", "FeatureFlags"]
