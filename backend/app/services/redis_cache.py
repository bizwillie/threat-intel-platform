"""
Redis Cache Integration (Phase 2.5 - Optional Feature)

Provides persistent caching for CVE data using Redis.

This module is OPTIONAL and controlled by the ENABLE_REDIS_CACHE feature flag.
If disabled, the system uses in-memory caching (non-persistent across restarts).
"""

import json
import logging
from typing import Optional, Any
from datetime import timedelta
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger(__name__)


class RedisCache:
    """
    Redis-based persistent cache for CVE data.

    Provides the same interface as the in-memory cache but persists across restarts.
    """

    _redis_client: Optional[aioredis.Redis] = None

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if Redis cache is enabled."""
        return settings.enable_redis_cache

    @classmethod
    async def _get_client(cls) -> Optional[aioredis.Redis]:
        """Get or create Redis client."""
        if not cls.is_enabled():
            return None

        if cls._redis_client is None:
            try:
                cls._redis_client = await aioredis.from_url(
                    settings.redis_url,
                    encoding="utf-8",
                    decode_responses=True
                )
                # Test connection
                await cls._redis_client.ping()
                logger.info(f"Connected to Redis at {settings.redis_url}")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                cls._redis_client = None

        return cls._redis_client

    @classmethod
    async def get(cls, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value (deserialized from JSON) or None if not found
        """
        if not cls.is_enabled():
            return None

        client = await cls._get_client()
        if not client:
            return None

        try:
            value = await client.get(key)
            if value is None:
                return None

            return json.loads(value)

        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None

    @classmethod
    async def set(cls, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl_seconds: Time-to-live in seconds (None = no expiration)

        Returns:
            True if successful, False otherwise
        """
        if not cls.is_enabled():
            return False

        client = await cls._get_client()
        if not client:
            return False

        try:
            serialized = json.dumps(value)

            if ttl_seconds:
                await client.setex(key, ttl_seconds, serialized)
            else:
                await client.set(key, serialized)

            return True

        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False

    @classmethod
    async def delete(cls, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if successful, False otherwise
        """
        if not cls.is_enabled():
            return False

        client = await cls._get_client()
        if not client:
            return False

        try:
            await client.delete(key)
            return True

        except Exception as e:
            logger.error(f"Redis DELETE error for key {key}: {e}")
            return False

    @classmethod
    async def exists(cls, key: str) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if exists, False otherwise
        """
        if not cls.is_enabled():
            return False

        client = await cls._get_client()
        if not client:
            return False

        try:
            result = await client.exists(key)
            return result > 0

        except Exception as e:
            logger.error(f"Redis EXISTS error for key {key}: {e}")
            return False

    @classmethod
    async def get_statistics(cls) -> dict:
        """Get Redis cache statistics."""
        if not cls.is_enabled():
            return {
                "enabled": False,
                "message": "Redis cache is disabled - using in-memory cache"
            }

        client = await cls._get_client()
        if not client:
            return {
                "enabled": True,
                "connected": False,
                "message": "Failed to connect to Redis"
            }

        try:
            info = await client.info("stats")
            dbsize = await client.dbsize()

            return {
                "enabled": True,
                "connected": True,
                "total_keys": dbsize,
                "total_commands_processed": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "hit_rate": (
                    info.get("keyspace_hits", 0) /
                    (info.get("keyspace_hits", 0) + info.get("keyspace_misses", 1))
                ) * 100 if info.get("keyspace_hits", 0) > 0 else 0.0,
            }

        except Exception as e:
            logger.error(f"Failed to get Redis statistics: {e}")
            return {
                "enabled": True,
                "connected": False,
                "error": str(e)
            }

    @classmethod
    async def close(cls) -> None:
        """Close Redis connection."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None
            logger.info("Redis connection closed")
