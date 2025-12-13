import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from models import User
from dbcrud import get_user_by_email
from unittest.mock import AsyncMock


class TestSignup:
    """Test user signup endpoint."""
    
    async def test_signup_success(self, client: AsyncClient, db_session: AsyncSession):
        """Test successful user signup."""
        response = await client.post(
            "/auth/signup",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "password123"
            }
        )
        assert response.status_code == 200
        assert response.json() == "User Created"
        
        # Verify user was created in database
        user = await get_user_by_email("newuser@example.com", db_session)
        assert user is not False
        assert user.email == "newuser@example.com"
        assert user.username == "newuser"
    
    async def test_signup_duplicate_email(self, client: AsyncClient, test_user: User):
        """Test signup with duplicate email."""
        response = await client.post(
            "/auth/signup",
            json={
                "email": test_user.email,
                "username": "different_username",
                "password": "password123"
            }
        )
        assert response.status_code == 409
        assert "Email already exists" in response.json()["detail"]
    
    async def test_signup_duplicate_username(self, client: AsyncClient, test_user: User):
        """Test signup with duplicate username."""
        response = await client.post(
            "/auth/signup",
            json={
                "email": "different@example.com",
                "username": test_user.username,
                "password": "password123"
            }
        )
        assert response.status_code == 409
        assert "Username already exists" in response.json()["detail"]
    
    async def test_signup_invalid_email(self, client: AsyncClient):
        """Test signup with invalid email format."""
        response = await client.post(
            "/auth/signup",
            json={
                "email": "invalid-email",
                "username": "testuser",
                "password": "password123"
            }
        )
        assert response.status_code == 422


class TestSignin:
    """Test user signin endpoint."""
    
    async def test_signin_success(self, client: AsyncClient, test_user: User, redis_mock):
        """Test successful signin."""
        # Mock Redis setex for refresh token storage
        redis_mock.setex = AsyncMock(return_value=True)
        
        response = await client.post(
            "/auth/signin",
            json={
                "email": test_user.email,
                "password": "testpassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        
        # Check that refresh token cookie was set
        cookies = response.cookies
        assert "refresh_token" in cookies
    
    async def test_signin_wrong_email(self, client: AsyncClient):
        """Test signin with non-existent email."""
        response = await client.post(
            "/auth/signin",
            json={
                "email": "nonexistent@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 400
        assert "User doesn't exists" in response.json()["detail"]
    
    async def test_signin_wrong_password(self, client: AsyncClient, test_user: User):
        """Test signin with wrong password."""
        response = await client.post(
            "/auth/signin",
            json={
                "email": test_user.email,
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 400
        assert "Email or Password is wrong!" in response.json()["detail"]


class TestAccessToken:
    """Test access token refresh endpoint."""
    
    async def test_access_token_success(self, client: AsyncClient, test_user: User, redis_mock):
        """Test successful access token refresh."""
        # First sign in to get refresh token cookie
        # The redis_mock will automatically store the refresh token
        response = await client.post(
            "/auth/signin",
            json={
                "email": test_user.email,
                "password": "testpassword123"
            }
        )
        assert response.status_code == 200
        
        # Now request new access token
        # The refresh token should be in the cookie and Redis
        response = await client.post("/auth/access")
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
    
    async def test_access_token_no_refresh_token(self, client: AsyncClient):
        """Test access token request without refresh token cookie."""
        response = await client.post("/auth/access")
        assert response.status_code == 400
        assert "token doesnt exists or expired" in response.json()["detail"]


class TestLogout:
    """Test logout endpoint."""
    
    async def test_logout_success(self, client: AsyncClient, test_user: User, redis_mock):
        """Test successful logout."""
        # First sign in to get refresh token cookie
        # The redis_mock will automatically store the refresh token
        response = await client.post(
            "/auth/signin",
            json={
                "email": test_user.email,
                "password": "testpassword123"
            }
        )
        assert response.status_code == 200
        
        # Now logout
        response = await client.post("/auth/logout")
        assert response.status_code == 200
        assert response.json() == "logout successfully"
    
    async def test_logout_no_token(self, client: AsyncClient):
        """Test logout without refresh token."""
        response = await client.post("/auth/logout")
        assert response.status_code == 200
        assert response.json() == "logout successfully"
