"""
Application configuration and feature flags.

Centralized configuration management for UTIP, including Phase 2.5 feature flags.
"""

import os
import logging
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, model_validator

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings with feature flags."""

    # Database
    database_url: str = Field(default="postgresql://utip:utip_password@postgres:5432/utip")

    # Redis
    redis_url: str = Field(default="redis://redis:6379/0")

    # Keycloak
    keycloak_url: str = Field(default="http://keycloak:8080")
    keycloak_realm: str = Field(default="utip")
    keycloak_client_id: str = Field(default="utip-api")
    keycloak_client_secret: str = Field(default="")

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_workers: int = Field(default=4)

    # Security
    secret_key: str = Field(default="change-me-in-production")
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)

    # Environment
    environment: str = Field(default="development")
    debug: bool = Field(default=True)

    # ========================================
    # PHASE 2.5 FEATURE FLAGS
    # ========================================

    # NVD API Integration
    enable_nvd_api: bool = Field(default=True, description="Query NVD API for live CVE data")
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API key (increases rate limit)")
    nvd_api_timeout: int = Field(default=10, description="NVD API request timeout in seconds")
    nvd_api_cache_ttl: int = Field(default=604800, description="NVD cache TTL in seconds (7 days)")

    # CAPEC Database Integration
    enable_capec_database: bool = Field(default=False, description="Use full CAPEC database")
    capec_data_path: str = Field(default="/app/data/capec.json", description="Path to CAPEC JSON file")

    # ATT&CK STIX Validation
    enable_attack_stix_validation: bool = Field(default=False, description="Validate techniques against STIX")
    attack_stix_path: str = Field(default="/app/data/enterprise-attack.json", description="Path to ATT&CK STIX bundle")

    # Redis Cache
    enable_redis_cache: bool = Field(default=False, description="Use Redis for persistent CVE cache")

    # Extended CWE Mappings
    enable_extended_cwe_mappings: bool = Field(default=False, description="Use 400+ CWE mappings")

    # Ollama (Phase 4 - Future)
    ollama_url: Optional[str] = Field(default=None)
    ollama_api_key: Optional[str] = Field(default=None)

    class Config:
        env_file = ".env"
        case_sensitive = False

    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """
        Validate secret key is not the default value and meets minimum length.

        SECURITY: Prevents deployment with default/weak secrets.
        """
        if v == "change-me-in-production":
            logger.warning(
                "SECRET_KEY is set to default value. "
                "This is acceptable for development but MUST be changed in production."
            )
        if len(v) < 32:
            logger.warning(
                f"SECRET_KEY is only {len(v)} characters. "
                "Recommend at least 32 characters for production security."
            )
        return v

    @field_validator('database_url')
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Validate database URL doesn't contain default credentials in suspicious contexts."""
        if "utip_password" in v:
            logger.warning(
                "Database URL contains default password 'utip_password'. "
                "Ensure this is changed in production."
            )
        return v

    @model_validator(mode='after')
    def validate_production_secrets(self) -> 'Settings':
        """
        Validate that production deployments don't use default secrets.

        SECURITY: This is a hard block - production CANNOT start with default secrets.
        """
        if self.environment.lower() == "production":
            errors = []

            if self.secret_key == "change-me-in-production":
                errors.append("SECRET_KEY must be changed from default in production")

            if len(self.secret_key) < 32:
                errors.append("SECRET_KEY must be at least 32 characters in production")

            if "utip_password" in self.database_url:
                errors.append("DATABASE_URL must not use default password in production")

            if errors:
                error_msg = "Production security validation failed:\n- " + "\n- ".join(errors)
                logger.error(error_msg)
                raise ValueError(error_msg)

            logger.info("Production security validation passed")

        return self

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment.lower() == "production"

    def get_async_database_url(self) -> str:
        """Get async database URL (asyncpg driver)."""
        if self.database_url.startswith("postgresql://"):
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings (for dependency injection)."""
    return settings
