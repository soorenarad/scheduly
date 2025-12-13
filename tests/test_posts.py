import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import Posts, PostApprovals, StatusPosts, OrgRole, UserOrgMemberships, Organizations, Channels, User
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock


class TestCreatePost:
    """Test post creation endpoint."""
    
    async def test_create_post_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession
    ):
        """Test successful post creation by owner."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        with patch('main.publish_post.apply_async') as mock_apply:
            mock_task = MagicMock()
            mock_task.id = "test_task_id"
            mock_apply.return_value = mock_task
            
            response = await client.post(
                f"/orgs/{test_org.id}/posts",
                json={
                    "channel_id": test_channel.id,
                    "body_text": "Test post content",
                    "media_url": "https://example.com/image.jpg",
                    "scheduled_at": scheduled_at.isoformat(),
                    "status": "queued"
                },
                headers=auth_headers
            )
            assert response.status_code == 200
            assert response.json()["message"] == "post scheduled"
            
            # Verify post was created
            result = await db_session.execute(
                select(Posts).where(Posts.org_id == test_org.id)
            )
            post = result.scalar_one_or_none()
            assert post is not None
            assert post.body_text == "Test post content"
            assert post.status == StatusPosts.queued
            assert post.approvals_required == False  # Owner doesn't need approval
            assert post.celery_task_id == "test_task_id"
    
    async def test_create_post_as_editor_requires_approval(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_channel: Channels, db_session: AsyncSession
    ):
        """Test post creation by editor (requires approval)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        with patch('main.publish_post.apply_async') as mock_apply:
            mock_task = MagicMock()
            mock_task.id = "test_task_id"
            mock_apply.return_value = mock_task
            
            response = await client.post(
                f"/orgs/{test_org.id}/posts",
                json={
                    "channel_id": test_channel.id,
                    "body_text": "Editor post",
                    "media_url": "https://example.com/image.jpg",
                    "scheduled_at": scheduled_at.isoformat(),
                    "status": "queued"
                },
                headers=editor_headers
            )
            assert response.status_code == 200
            
            # Verify post requires approval
            result = await db_session.execute(
                select(Posts).where(Posts.author_user_id == editor_user.id)
            )
            post = result.scalar_one_or_none()
            assert post.approvals_required == True
    
    async def test_create_post_as_viewer_fails(
        self, client: AsyncClient, test_org: Organizations, viewer_user: User,
        test_channel: Channels
    ):
        """Test post creation by viewer (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": viewer_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        response = await client.post(
            f"/orgs/{test_org.id}/posts",
            json={
                "channel_id": test_channel.id,
                "body_text": "Viewer post",
                "media_url": "https://example.com/image.jpg",
                "scheduled_at": scheduled_at.isoformat(),
                "status": "queued"
            },
            headers=viewer_headers
        )
        assert response.status_code == 400
        assert "Viewer can not create post" in response.json()["detail"]
    
    async def test_create_post_unauthorized(self, client: AsyncClient, test_org: Organizations, test_channel: Channels):
        """Test post creation without authentication."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        response = await client.post(
            f"/orgs/{test_org.id}/posts",
            json={
                "channel_id": test_channel.id,
                "body_text": "Test post",
                "media_url": "https://example.com/image.jpg",
                "scheduled_at": scheduled_at.isoformat(),
                "status": "queued"
            }
        )
        assert response.status_code == 401


class TestListPosts:
    """Test list posts endpoint."""
    
    async def test_list_posts_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test successful post listing."""
        # Create some test posts
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post1 = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post 1",
            media_url="https://example.com/1.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=False
        )
        post2 = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post 2",
            media_url="https://example.com/2.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.draft,
            approvals_required=False
        )
        db_session.add_all([post1, post2])
        await db_session.commit()
        
        response = await client.get(
            f"/orgs/{test_org.id}/posts/{test_channel.id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "page" in data
        assert "page_size" in data
        assert "total" in data
        assert "posts" in data
        assert data["total"] >= 2
    
    async def test_list_posts_with_status_filter(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post listing with status filter."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Draft post",
            media_url="https://example.com/draft.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.draft,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        
        response = await client.get(
            f"/orgs/{test_org.id}/posts/{test_channel.id}?status=draft",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert all(p["status"] == "draft" for p in data["posts"])
    
    async def test_list_posts_pagination(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post listing with pagination."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Create multiple posts
        posts = []
        for i in range(5):
            post = Posts(
                org_id=test_org.id,
                channel_id=test_channel.id,
                author_user_id=test_user.id,
                body_text=f"Post {i}",
                media_url=f"https://example.com/{i}.jpg",
                scheduled_at=scheduled_at,
                status=StatusPosts.queued,
                approvals_required=False
            )
            posts.append(post)
        db_session.add_all(posts)
        await db_session.commit()
        
        response = await client.get(
            f"/orgs/{test_org.id}/posts/{test_channel.id}?page=1&page_size=2",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["posts"]) <= 2
    
    async def test_list_posts_nonexistent_org(
        self, client: AsyncClient, auth_headers: dict, test_channel: Channels
    ):
        """Test listing posts for non-existent organization."""
        response = await client.get(
            f"/orgs/99999/posts/{test_channel.id}",
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "Organization does not exist" in response.json()["detail"]


class TestEditPost:
    """Test edit post endpoint."""
    
    async def test_edit_post_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test successful post editing."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Original text",
            media_url="https://example.com/original.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.draft,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}",
            json={
                "body": "Updated text",
                "media": "https://example.com/updated.jpg",
                "status": "queued"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Post updated successfully"
        
        # Verify post was updated
        await db_session.refresh(post)
        assert post.body_text == "Updated text"
        assert post.media_url == "https://example.com/updated.jpg"
        assert post.status == StatusPosts.queued
    
    async def test_edit_post_as_viewer_fails(
        self, client: AsyncClient, test_org: Organizations, viewer_user: User,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post editing by viewer (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": viewer_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Original text",
            media_url="https://example.com/original.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.draft,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}",
            json={"body": "Updated text"},
            headers=viewer_headers
        )
        assert response.status_code == 403
        assert "user not allowed to edit posts" in response.json()["detail"]
    
    async def test_edit_published_post_fails(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test editing published post (should fail)."""
        scheduled_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Published post",
            media_url="https://example.com/published.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.published,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}",
            json={"body": "Updated text"},
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "already published or is being published" in response.json()["detail"]
    
    async def test_edit_nonexistent_post(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test editing non-existent post."""
        response = await client.post(
            "/posts/99999",
            json={"body": "Updated text"},
            headers=auth_headers
        )
        assert response.status_code == 404
        assert "Post doesn't exists" in response.json()["detail"]


class TestApprovePost:
    """Test approve post endpoint."""
    
    async def test_approve_post_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test successful post approval by owner."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post requiring approval",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=True
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}/approve",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert "approved" in response.json().lower()
        
        # Verify approval was created
        result = await db_session.execute(
            select(PostApprovals).where(PostApprovals.post_id == post.id)
        )
        approval = result.scalar_one_or_none()
        assert approval is not None
    
    async def test_approve_post_already_approved(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test approving already approved post."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post requiring approval",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=True
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        # First approval
        response = await client.post(
            f"/posts/{post.id}/approve",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # Second approval attempt
        response = await client.post(
            f"/posts/{post.id}/approve",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert "already approved" in response.json().lower()
    
    async def test_approve_post_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post approval by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post requiring approval",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=True
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}/approve",
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "not allowed to approve" in response.json()["detail"]


class TestCancelPost:
    """Test cancel post endpoint."""
    
    async def test_cancel_post_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test successful post cancellation by owner."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post to cancel",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=False,
            celery_task_id="test_task_id"
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        # Mock celery_app.control.revoke
        mock_control = MagicMock()
        mock_control.revoke = MagicMock()
        
        with patch('main.celery_app.control', mock_control):
            response = await client.post(
                f"/posts/{post.id}/cancel",
                headers=auth_headers
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Post canceled successfully"
            
            # Verify post status was updated
            await db_session.refresh(post)
            assert post.status == StatusPosts.canceled
    
    async def test_cancel_post_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post cancellation by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post to cancel",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}/cancel",
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "not allowed to cancel" in response.json()["detail"]


class TestPublishPost:
    """Test publish post immediately endpoint."""
    
    async def test_publish_post_success(
        self, client: AsyncClient, auth_headers: dict, test_org: Organizations,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test successful immediate post publishing by owner."""
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post to publish",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}/publish",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Post published successfully"
        
        # Verify post status was updated
        await db_session.refresh(post)
        assert post.status == StatusPosts.published
    
    async def test_publish_post_insufficient_permission(
        self, client: AsyncClient, test_org: Organizations, editor_user: User,
        test_channel: Channels, db_session: AsyncSession, test_user: User
    ):
        """Test post publishing by editor (should fail)."""
        response = await client.post(
            "/auth/signin",
            json={"email": editor_user.email, "password": "testpassword123"}
        )
        token = response.json()["access_token"]
        editor_headers = {"Authorization": f"Bearer {token}"}
        
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        post = Posts(
            org_id=test_org.id,
            channel_id=test_channel.id,
            author_user_id=test_user.id,
            body_text="Post to publish",
            media_url="https://example.com/post.jpg",
            scheduled_at=scheduled_at,
            status=StatusPosts.queued,
            approvals_required=False
        )
        db_session.add(post)
        await db_session.commit()
        await db_session.refresh(post)
        
        response = await client.post(
            f"/posts/{post.id}/publish",
            headers=editor_headers
        )
        assert response.status_code == 403
        assert "not allowed to publish" in response.json()["detail"]
