"""
Database connection and session management.

Provides async database session factory for FastAPI dependencies.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os
import logging

logger = logging.getLogger(__name__)

# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://utip:utip_password@postgres:5432/utip")

# Convert to async URL (asyncpg driver)
if DATABASE_URL.startswith("postgresql://"):
    ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
else:
    ASYNC_DATABASE_URL = DATABASE_URL

# PERFORMANCE: Connection pool configuration for production
# pool_size: Number of connections to keep open permanently
# max_overflow: Max temporary connections beyond pool_size
# pool_timeout: Seconds to wait for a connection from pool
# pool_recycle: Seconds before connection is recycled (prevents stale connections)
# pool_pre_ping: Test connections before use (handles disconnects)
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_pre_ping=True,  # Verify connections before using
    pool_size=20,  # Increased from 10 for production workloads
    max_overflow=10,  # Reduced from 20 to limit connection spikes
    pool_timeout=30,  # Wait 30s max for a connection
    pool_recycle=1800,  # Recycle connections every 30 minutes
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncSession:
    """
    FastAPI dependency for database sessions.

    Usage:
        @router.get("/endpoint")
        async def my_endpoint(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(Model))
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()
