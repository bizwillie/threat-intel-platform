"""
UTIP Backend Test Configuration

Provides fixtures for:
- Test database (SQLite in-memory)
- Test client (async httpx)
- Mock authentication
- Sample data factories
"""

import asyncio
import os
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment before importing app
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["KEYCLOAK_URL"] = "http://test-keycloak:8080"
os.environ["KEYCLOAK_REALM"] = "test-realm"
os.environ["KEYCLOAK_CLIENT_ID"] = "test-client"

from app.main import app
from app.database import Base, get_db


# Test database engine (SQLite in-memory)
test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh database session for each test.

    Creates all tables at the start and drops them after.
    """
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session
        await session.rollback()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    Create an async HTTP client with overridden database dependency.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authenticated_client(client: AsyncClient) -> AsyncClient:
    """
    Create an authenticated client with mocked JWT validation.
    """
    # Mock the Keycloak authentication
    mock_user = {
        "username": "test_analyst",
        "email": "analyst@test.local",
        "roles": ["analyst"],
        "user_id": "test-user-uuid"
    }

    with patch("app.auth.keycloak.get_current_user") as mock_auth:
        from app.auth.keycloak import User
        mock_auth.return_value = User(
            username=mock_user["username"],
            email=mock_user["email"],
            roles=mock_user["roles"],
            user_id=mock_user["user_id"]
        )
        yield client


@pytest_asyncio.fixture
async def admin_client(client: AsyncClient) -> AsyncClient:
    """
    Create an admin-authenticated client.
    """
    mock_user = {
        "username": "test_admin",
        "email": "admin@test.local",
        "roles": ["admin", "analyst"],
        "user_id": "admin-user-uuid"
    }

    with patch("app.auth.keycloak.get_current_user") as mock_auth:
        from app.auth.keycloak import User
        mock_auth.return_value = User(
            username=mock_user["username"],
            email=mock_user["email"],
            roles=mock_user["roles"],
            user_id=mock_user["user_id"]
        )
        yield client


# Sample data factories
class SampleData:
    """Factory for generating test data."""

    @staticmethod
    def intel_report(
        title: str = "Test APT Report",
        source: str = "Test Source",
        content: str = "APT29 uses T1566 phishing for initial access."
    ) -> dict:
        return {
            "title": title,
            "source": source,
            "content": content
        }

    @staticmethod
    def vulnerability(
        cve_id: str = "CVE-2024-1234",
        severity: str = "HIGH",
        description: str = "Test vulnerability"
    ) -> dict:
        return {
            "cve_id": cve_id,
            "severity": severity,
            "description": description
        }

    @staticmethod
    def layer(
        name: str = "Test Layer",
        description: str = "Test correlation layer"
    ) -> dict:
        return {
            "name": name,
            "description": description,
            "intel_report_ids": [],
            "vuln_scan_ids": []
        }


@pytest.fixture
def sample_data() -> SampleData:
    """Provide sample data factory."""
    return SampleData()
