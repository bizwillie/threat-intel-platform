"""
Application configuration and feature flags.

Centralized configuration management for UTIP, including Phase 2.5 feature flags.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


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
