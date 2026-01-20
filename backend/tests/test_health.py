"""
Tests for health check endpoints.

These tests verify the basic API availability and health status.
"""

import pytest
from httpx import AsyncClient


class TestHealthEndpoints:
    """Test suite for health check endpoints."""

    @pytest.mark.asyncio
    async def test_health_check_returns_healthy(self, client: AsyncClient):
        """Health endpoint should return healthy status."""
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "utip-core-api"
        assert "version" in data

    @pytest.mark.asyncio
    async def test_root_endpoint_returns_api_info(self, client: AsyncClient):
        """Root endpoint should return API information."""
        response = await client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "UTIP Core API"
        assert "version" in data
        assert "docs" in data

    @pytest.mark.asyncio
    async def test_docs_endpoint_available(self, client: AsyncClient):
        """OpenAPI docs should be accessible."""
        response = await client.get("/docs")

        # Docs return HTML, so we just check it's accessible
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_openapi_schema_available(self, client: AsyncClient):
        """OpenAPI JSON schema should be accessible."""
        response = await client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "paths" in data


class TestSecurityHeaders:
    """Test that security headers are present in responses."""

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_security_headers_present(self, client: AsyncClient):
        """All security headers should be present."""
        response = await client.get("/health")

        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert "X-Request-ID" in response.headers
        assert response.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_request_id_is_unique(self, client: AsyncClient):
        """Each request should get a unique request ID."""
        response1 = await client.get("/health")
        response2 = await client.get("/health")

        request_id_1 = response1.headers.get("X-Request-ID")
        request_id_2 = response2.headers.get("X-Request-ID")

        assert request_id_1 is not None
        assert request_id_2 is not None
        assert request_id_1 != request_id_2

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_referrer_policy_present(self, client: AsyncClient):
        """Referrer-Policy header should be set."""
        response = await client.get("/health")

        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_permissions_policy_present(self, client: AsyncClient):
        """Permissions-Policy header should restrict features."""
        response = await client.get("/health")

        policy = response.headers.get("Permissions-Policy")
        assert policy is not None
        assert "geolocation=()" in policy
        assert "camera=()" in policy
