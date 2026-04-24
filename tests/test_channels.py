import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Channels, Providers, OrgRole, UserOrgMemberships, Organizations, User


class TestCreateChannel:
    """Test channel creation endpoint."""
    
    async def test_create_channel_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        db_session: AsyncSession
    ):
        """Test successful channel creation by owner."""
        response = await client.post(
            f"/orgs/{test_org.id}/channels/oauth",
            json={
                "provider": "twt",
                "display_name": "Twitter Channel"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "fake_oauth_url" in data
        
        # Verify channel was created
        result = await db_session.execute(
            select(Channels).where(Channels.org_id == test_org.id)
        )
        channel = result.scalar_one_or_none()
        assert channel is not None
        assert channel.provider == Providers.twt
        assert channel.display_name == "Twitter Channel"
        assert channel.is_active == False
    
    async def test_create_channel_as_admin(
        self, client: AsyncClient, test_org: Organizations, admin_user: User,
        redis_mock
    ):
        """Test channel creation by admin."""
        response = await client.post(
            "/auth/signin",
            json={"email": admin_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.post(
            f"/orgs/{test_org.id}/channels/oauth",
            json={
                "provider": "insta",
                "display_name": "Instagram Channel"
            },
            headers=admin_headers
        )
        assert response.status_code == 200
    
    async def test_create_channel_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User
    ):
        """Test channel creation by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.post(
            f"/orgs/{test_org.id}/channels/oauth",
            json={
                "provider": "twt",
                "display_name": "Twitter Channel"
            },
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "not enough permission" in response.json()["detail"]
    
    async def test_create_channel_unauthorized(self, client: AsyncClient, test_org: Organizations):
        """Test channel creation without authentication."""
        response = await client.post(
            f"/orgs/{test_org.id}/channels/oauth",
            json={
                "provider": "twt",
                "display_name": "Twitter Channel"
            }
        )
        assert response.status_code == 401


class TestOAuthCallback:
    """Test OAuth callback endpoint."""
    
    async def test_oauth_callback_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession
    ):
        """Test successful OAuth callback."""
        # Channel should start as inactive
        assert test_channel.is_active == True  # From fixture, but let's test with inactive
        
        # Create an inactive channel for this test
        inactive_channel = Channels(
            org_id=test_org.id,
            provider=Providers.insta,
            display_name="Inactive Channel",
            is_active=False
        )
        db_session.add(inactive_channel)
        await db_session.commit()
        await db_session.refresh(inactive_channel)
        
        response = await client.post(
            f"/orgs/{test_org.id}/channels/{inactive_channel.id}/oauth/callback",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json() == "Channel connected successfully"
        
        # Verify channel is now active
        await db_session.refresh(inactive_channel)
        assert inactive_channel.is_active == True
        assert inactive_channel.access_token_enc == "fake_access_token"
        assert inactive_channel.refresh_token_enc == "fake_refresh_token"
    
    async def test_oauth_callback_nonexistent_channel(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations
    ):
        """Test OAuth callback for non-existent channel."""
        response = await client.post(
            f"/orgs/{test_org.id}/channels/99999/oauth/callback",
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "such channel doesnt exists" in response.json()["detail"]


class TestGetChannels:
    """Test get channels endpoint."""
    
    async def test_get_channels_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels
    ):
        """Test successful retrieval of channels."""
        response = await client.get(
            f"/orgs/{test_org.id}/channels",
            headers=auth_headers
        )
        assert response.status_code == 200
        channels = response.json()
        assert isinstance(channels, list)
        assert len(channels) >= 1
        assert any(ch["id"] == test_channel.id for ch in channels)
    
    async def test_get_channels_empty(
        self, client: AsyncClient, auth_headers: dict, test_user: User,
        db_session: AsyncSession
    ):
        """Test getting channels for org with no channels."""
        # Create a new org without channels
        from models import UserOrgMemberships
        
        new_org = Organizations(name="Empty Org")
        db_session.add(new_org)
        await db_session.commit()
        await db_session.refresh(new_org)
        
        # Add user as owner
        membership = UserOrgMemberships(
            user_id=test_user.id,
            org_id=new_org.id,
            role=OrgRole.owner
        )
        db_session.add(membership)
        await db_session.commit()
        
        response = await client.get(
            f"/orgs/{new_org.id}/channels",
            headers=auth_headers
        )
        assert response.status_code == 200
        channels = response.json()
        assert isinstance(channels, list)
        assert len(channels) == 0
    
    async def test_get_channels_unauthorized(self, client: AsyncClient, test_org: Organizations):
        """Test get channels without authentication."""
        response = await client.get(f"/orgs/{test_org.id}/channels")
        assert response.status_code == 401


class TestDeleteChannel:
    """Test delete channel endpoint."""
    
    async def test_delete_channel_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession
    ):
        """Test successful channel deletion by owner."""
        channel_id = test_channel.id
        
        response = await client.delete(
            f"/channels/{channel_id}?org_id={test_org.id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Channel deleted successfully"
        
        # Verify channel was deleted
        result = await db_session.execute(
            select(Channels).where(Channels.id == channel_id)
        )
        channel = result.scalar_one_or_none()
        assert channel is None
    
    async def test_delete_channel_as_admin(
        self, client: AsyncClient, test_org: Organizations, admin_user: User,
        test_channel: Channels, db_session: AsyncSession
    ):
        """Test channel deletion by admin."""
        response = await client.post(
            "/auth/signin",
            json={"email": admin_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {token}"}
        
        # Create a new channel for deletion
        new_channel = Channels(
            org_id=test_org.id,
            provider=Providers.twt,
            display_name="Channel to Delete",
            is_active=True
        )
        db_session.add(new_channel)
        await db_session.commit()
        await db_session.refresh(new_channel)
        
        response = await client.delete(
            f"/channels/{new_channel.id}?org_id={test_org.id}",
            headers=admin_headers
        )
        assert response.status_code == 200
    
    async def test_delete_channel_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_channel: Channels
    ):
        """Test channel deletion by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.delete(
            f"/channels/{test_channel.id}?org_id={test_org.id}",
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "not enough permission" in response.json()["detail"]
    
    async def test_delete_nonexistent_channel(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations
    ):
        """Test deletion of non-existent channel."""
        response = await client.delete(
            f"/channels/99999?org_id={test_org.id}",
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "channel doesn't exists" in response.json()["detail"]
    
    async def test_delete_channel_unauthorized(self, client: AsyncClient, test_org: Organizations, test_channel: Channels):
        """Test channel deletion without authentication."""
        response = await client.delete(f"/channels/{test_channel.id}?org_id={test_org.id}")
        assert response.status_code == 401
