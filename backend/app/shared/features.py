"""
Feature Flag Utilities

Provides convenient access to Phase 2.5 feature flags with lazy service initialization.
This centralizes feature checking logic that was previously scattered across services.

Usage:
    from app.shared.features import features

    if features.nvd_api_enabled:
        # Use NVD API

    if features.is_enabled('capec_database'):
        # Use CAPEC database
"""

import logging
from typing import Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)


class FeatureFlags:
    """
    Centralized feature flag access with lazy initialization support.

    All Phase 2.5 features can be checked through this class.
    """

    # Feature flag names mapped to settings attributes
    _FLAG_MAP = {
        'nvd_api': 'enable_nvd_api',
        'capec_database': 'enable_capec_database',
        'attack_stix_validation': 'enable_attack_stix_validation',
        'redis_cache': 'enable_redis_cache',
        'extended_cwe_mappings': 'enable_extended_cwe_mappings',
    }

    @property
    def nvd_api_enabled(self) -> bool:
        """Check if NVD API integration is enabled."""
        return settings.enable_nvd_api

    @property
    def capec_database_enabled(self) -> bool:
        """Check if CAPEC database is enabled."""
        return settings.enable_capec_database

    @property
    def attack_stix_enabled(self) -> bool:
        """Check if ATT&CK STIX validation is enabled."""
        return settings.enable_attack_stix_validation

    @property
    def redis_cache_enabled(self) -> bool:
        """Check if Redis cache is enabled."""
        return settings.enable_redis_cache

    @property
    def extended_cwe_enabled(self) -> bool:
        """Check if extended CWE mappings are enabled."""
        return settings.enable_extended_cwe_mappings

    def is_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled by name.

        Args:
            feature_name: Short name of the feature (e.g., 'nvd_api', 'capec_database')

        Returns:
            True if the feature is enabled, False otherwise
        """
        attr_name = self._FLAG_MAP.get(feature_name)
        if attr_name is None:
            logger.warning(f"Unknown feature flag: {feature_name}")
            return False
        return getattr(settings, attr_name, False)

    def get_status(self) -> Dict[str, bool]:
        """
        Get status of all feature flags.

        Returns:
            Dict mapping feature names to their enabled status
        """
        return {
            name: getattr(settings, attr, False)
            for name, attr in self._FLAG_MAP.items()
        }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detailed statistics about feature flags.

        Returns:
            Dict containing feature status and configuration details
        """
        return {
            "features": {
                "nvd_api": {
                    "enabled": settings.enable_nvd_api,
                    "has_api_key": bool(settings.nvd_api_key),
                    "timeout": settings.nvd_api_timeout,
                    "cache_ttl": settings.nvd_api_cache_ttl,
                },
                "capec_database": {
                    "enabled": settings.enable_capec_database,
                    "data_path": settings.capec_data_path,
                },
                "attack_stix_validation": {
                    "enabled": settings.enable_attack_stix_validation,
                    "stix_path": settings.attack_stix_path,
                },
                "redis_cache": {
                    "enabled": settings.enable_redis_cache,
                    "url_configured": bool(settings.redis_url),
                },
                "extended_cwe_mappings": {
                    "enabled": settings.enable_extended_cwe_mappings,
                },
            },
            "enabled_count": sum(1 for v in self.get_status().values() if v),
            "total_features": len(self._FLAG_MAP),
        }

    def log_status(self) -> None:
        """Log current feature flag status."""
        status = self.get_status()
        enabled = [k for k, v in status.items() if v]
        disabled = [k for k, v in status.items() if not v]

        logger.info(f"Feature flags - Enabled: {enabled}, Disabled: {disabled}")


# Singleton instance for easy import
features = FeatureFlags()
