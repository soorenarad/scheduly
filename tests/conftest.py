import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from main import app, get_db
from db import Base
from models import User, Organizations, UserOrgMemberships, Channels, Posts, PostApprovals
from models import OrgRole, Providers, StatusPosts
from dbcrud import hash_password
import redis.asyncio as redis
from unittest.mock import AsyncMock, MagicMock, patch


# Test database URL (using in-memory SQLite for testing)
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

# Create test engine
test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with TestSessionLocal() as session:
        yield session
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(scope="function")
async def redis_mock():
    """Mock Redis client for testing."""
    # Use a dict to store tokens
    token_store = {}
    
    mock_redis = AsyncMock(spec=redis.Redis)
    
    async def mock_get(key):
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        value = token_store.get(key)
        if value is not None:
            # Return as bytes to match Redis behavior
            if isinstance(value, str):
                return value.encode('utf-8')
            return value
        return None
    
    async def mock_setex(key, ttl, value):
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        # Store as string, but we'll return as bytes when retrieved
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        token_store[key] = value
        return True
    
    async def mock_delete(key):
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        elif isinstance(key, tuple):
            key = key[0] if key else None
        if key and key in token_store:
            del token_store[key]
            return 1
        return 0
    
    mock_redis.get = mock_get
    mock_redis.setex = mock_setex
    mock_redis.delete = mock_delete
    
    return mock_redis


@pytest.fixture(scope="function")
async def client(db_session: AsyncSession, redis_mock) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with overridden dependencies."""
    
    async def override_get_db():
        yield db_session
    
    async def override_get_redis():
        return redis_mock
    
    from main import get_redis
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    
    # Note: Real JWT tokens should work if settings are correct
    # If tokens fail, check that SECRET_KEY_ACCESS and ALGORITHM match
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        password=hash_password("testpassword123")
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_user2(db_session: AsyncSession) -> User:
    """Create a second test user."""
    user = User(
        email="test2@example.com",
        username="testuser2",
        password=hash_password("testpassword123")
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_org(db_session: AsyncSession, test_user: User) -> Organizations:
    """Create a test organization with owner."""
    org = Organizations(name="Test Organization")
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    
    membership = UserOrgMemberships(
        user_id=test_user.id,
        org_id=org.id,
        role=OrgRole.owner
    )
    db_session.add(membership)
    await db_session.commit()
    
    return org


@pytest.fixture
async def test_channel(db_session: AsyncSession, test_org: Organizations) -> Channels:
    """Create a test channel."""
    channel = Channels(
        org_id=test_org.id,
        provider=Providers.twt,
        display_name="Test Channel",
        is_active=True
    )
    db_session.add(channel)
    await db_session.commit()
    await db_session.refresh(channel)
    return channel


@pytest.fixture
async def auth_headers(client: AsyncClient, test_user: User, redis_mock) -> dict:
    """Get authentication headers for test user."""
    # Mock Redis setex for refresh token storage
    redis_mock.setex = AsyncMock(return_value=True)
    
    # Sign in to get access token
    response = await client.post(
        "/auth/signin",
        json={"email": test_user.email, "password": "testpassword123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin_user(db_session: AsyncSession, test_org: Organizations, test_user2: User) -> User:
    """Create an admin user in the organization."""
    membership = UserOrgMemberships(
        user_id=test_user2.id,
        org_id=test_org.id,
        role=OrgRole.admin
    )
    db_session.add(membership)
    await db_session.commit()
    return test_user2


@pytest.fixture
async def editor_user(db_session: AsyncSession, test_org: Organizations) -> User:
    """Create an editor user in the organization."""
    user = User(
        email="editor@example.com",
        username="editoruser",
        password=hash_password("testpassword123")
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    membership = UserOrgMemberships(
        user_id=user.id,
        org_id=test_org.id,
        role=OrgRole.editor
    )
    db_session.add(membership)
    await db_session.commit()
    return user


@pytest.fixture
async def viewer_user(db_session: AsyncSession, test_org: Organizations) -> User:
    """Create a viewer user in the organization."""
    user = User(
        email="viewer@example.com",
        username="vieweruser",
        password=hash_password("testpassword123")
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    membership = UserOrgMemberships(
        user_id=user.id,
        org_id=test_org.id,
        role=OrgRole.viewer
    )
    db_session.add(membership)
    await db_session.commit()
    return user
