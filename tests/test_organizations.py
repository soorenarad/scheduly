import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Organizations, UserOrgMemberships, OrgRole, User


class TestCreateOrganization:
    """Test organization creation endpoint."""
    
    async def test_create_org_success(self, client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
        """Test successful organization creation."""
        response = await client.post(
            "/orgs",
            json={"name": "New Organization"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["org_name"] == "New Organization"
        assert "user_id" in data
        
        # Verify organization was created
        result = await db_session.execute(
            select(Organizations).where(Organizations.name == "New Organization")
        )
        org = result.scalar_one_or_none()
        assert org is not None
        
        # Verify user is owner
        result = await db_session.execute(
            select(UserOrgMemberships).where(
                UserOrgMemberships.org_id == org.id
            )
        )
        membership = result.scalar_one_or_none()
        assert membership is not None
        assert membership.role == OrgRole.owner
    
    async def test_create_org_unauthorized(self, client: AsyncClient):
        """Test organization creation without authentication."""
        response = await client.post(
            "/orgs",
            json={"name": "New Organization"}
        )
        assert response.status_code == 401


class TestGetOrgMembers:
    """Test get organization members endpoint."""
    
    async def test_get_members_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_user: User, admin_user: User, db_session: AsyncSession
    ):
        """Test successful retrieval of organization members."""
        response = await client.get(
            f"/orgs/{test_org.id}/members",
            headers=auth_headers
        )
        assert response.status_code == 200
        members = response.json()
        assert isinstance(members, dict)
        assert test_user.username in members
        assert members[test_user.username] == "owner"
        assert admin_user.username in members
        assert members[admin_user.username] == "admin"
    
    async def test_get_members_unauthorized(self, client: AsyncClient, test_org: Organizations):
        """Test get members without authentication."""
        response = await client.get(f"/orgs/{test_org.id}/members")
        assert response.status_code == 401


class TestInviteMember:
    """Test invite member endpoint."""
    
    async def test_invite_member_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_user2: User, db_session: AsyncSession
    ):
        """Test successful member invitation by owner."""
        response = await client.post(
            f"/orgs/{test_org.id}/invite",
            json={
                "email": test_user2.email,
                "role": "editor"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json() == "User added successfully"
        
        # Verify membership was created
        result = await db_session.execute(
            select(UserOrgMemberships).where(
                UserOrgMemberships.org_id == test_org.id,
                UserOrgMemberships.user_id == test_user2.id
            )
        )
        membership = result.scalar_one_or_none()
        assert membership is not None
        assert membership.role == OrgRole.editor
    
    async def test_invite_member_as_admin(
        self, client: AsyncClient, test_org: Organizations, admin_user: User,
        test_user2: User, db_session: AsyncSession, redis_mock
    ):
        """Test member invitation by admin."""
        # Get auth headers for admin user
        response = await client.post(
            "/auth/signin",
            json={"email": admin_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.post(
            f"/orgs/{test_org.id}/invite",
            json={
                "email": test_user2.email,
                "role": "viewer"
            },
            headers=admin_headers
        )
        assert response.status_code == 200
    
    async def test_invite_member_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_user2: User, redis_mock
    ):
        """Test member invitation by editor (should fail)."""
        # Get auth headers for editor user
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.post(
            f"/orgs/{test_org.id}/invite",
            json={
                "email": test_user2.email,
                "role": "viewer"
            },
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "Role not high enough" in response.json()["detail"]
    
    async def test_invite_member_nonexistent_org(
        self, client: AsyncClient, auth_headers: dict, test_user2: User
    ):
        """Test invite member to non-existent organization."""
        response = await client.post(
            "/orgs/99999/invite",
            json={
                "email": test_user2.email,
                "role": "editor"
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "organization doesn't exists" in response.json()["detail"]
    
    async def test_invite_nonexistent_user(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations
    ):
        """Test invite non-existent user."""
        response = await client.post(
            f"/orgs/{test_org.id}/invite",
            json={
                "email": "nonexistent@example.com",
                "role": "editor"
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "target user doesn't exists" in response.json()["detail"]


class TestChangeRole:
    """Test change member role endpoint."""
    
    async def test_change_role_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        admin_user: User, db_session: AsyncSession
    ):
        """Test successful role change by owner."""
        response = await client.patch(
            f"/orgs/{test_org.id}/members/{admin_user.id}",
            json={"new_role": "editor"},
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json() == "role changed successfully"
        
        # Verify role was changed
        result = await db_session.execute(
            select(UserOrgMemberships).where(
                UserOrgMemberships.org_id == test_org.id,
                UserOrgMemberships.user_id == admin_user.id
            )
        )
        membership = result.scalar_one_or_none()
        assert membership.role == OrgRole.editor
    
    async def test_change_role_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        admin_user: User, redis_mock
    ):
        """Test role change by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        response = await client.patch(
            f"/orgs/{test_org.id}/members/{admin_user.id}",
            json={"new_role": "viewer"},
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "Role not high enough" in response.json()["detail"]
    
    async def test_change_owner_role(self, client: AsyncClient, auth_headers: dict, test_org: Organizations, test_user: User):
        """Test changing owner role (should fail)."""
        response = await client.patch(
            f"/orgs/{test_org.id}/members/{test_user.id}",
            json={"new_role": "admin"},
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "already owner and can not be changed" in response.json()["detail"]
    
    async def test_change_own_role(self, client: AsyncClient, auth_headers: dict, test_org: Organizations, test_user: User):
        """Test user changing their own role (should fail)."""
        response = await client.patch(
            f"/orgs/{test_org.id}/members/{test_user.id}",
            json={"new_role": "admin"},
            headers=auth_headers
        )
        assert response.status_code in [400, 403]  # Either owner can't be changed or can't change own role
    
    async def test_change_role_nonexistent_member(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations
    ):
        """Test changing role for non-member."""
        response = await client.patch(
            f"/orgs/{test_org.id}/members/99999",
            json={"new_role": "editor"},
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "not a member of this organization" in response.json()["detail"]
