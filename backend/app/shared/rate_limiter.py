"""
Shared Rate Limiter

Centralized rate limiter instance to be used across all routes.
This prevents duplicate Limiter instantiation and ensures consistent rate limiting.

SECURITY: Rate limiting prevents:
- Brute force attacks
- DoS via resource exhaustion
- API abuse
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Single shared limiter instance
# All routes should import and use this instance
limiter = Limiter(key_func=get_remote_address)
