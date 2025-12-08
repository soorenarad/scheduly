# Standard library
import uuid
from typing import Optional, AsyncGenerator
from datetime import datetime

# Third-party
from fastapi import FastAPI, Depends, HTTPException, Response, Request, status, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

# Local app imports
from db import AsyncSessionLocal
import models
from dbcrud import create_user, get_user_by_email, verify_password
from jwt_manual import create_access_token, create_refresh_token, verify_token
from jose import JWTError
from models import OrgRole, Providers, StatusPosts
from celery_task import publish_post
from setting import settings
import celery_app

app = FastAPI()

redis_handle = redis.Redis(
    host=settings.Redis_host,
    port=settings.Redis_port,
    db=0,
    max_connections=10  # Redis connection pool
)
async def get_redis():
    """Get Redis connection instance.
    
    Returns:
        redis.Redis: Redis client instance.
    """
    return redis_handle


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Database dependency for FastAPI endpoints.

    Creates a database session and yields it to the endpoint.
    Ensures the session is properly closed after use.

    Yields:
        AsyncSession: SQLAlchemy async database session.

    Raises:
        HTTPException: If there's an error connecting to the database.
    """
    try:
        async with AsyncSessionLocal() as db:
            yield db
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error connecting to database: {e}")

class UserSignUp(BaseModel):
    email: EmailStr
    username: str
    password: str

@app.post("/auth/signup")
async def signup(user: UserSignUp, db: AsyncSession = Depends(get_db)):
    """Create a new user account.
    
    Args:
        user: UserSignUp model containing email, username, and password.
        db: Database session dependency.
        
    Returns:
        str: Success message indicating user was created.
        
    Raises:
        HTTPException: If username or email already exists, or if user creation fails.
    """
    await create_user(db, user.username, user.email, user.password)

    return "User Created"

class UserSignIn(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/signin")
async def signin(response: Response, user: UserSignIn, db: AsyncSession = Depends(get_db), r: redis.Redis = Depends(get_redis)):
    """Authenticate user and generate access/refresh tokens.
    
    Validates user credentials and creates JWT tokens. Sets refresh token as HTTP-only cookie.
    
    Args:
        response: FastAPI Response object for setting cookies.
        user: UserSignIn model containing email and password.
        db: Database session dependency.
        r: Redis client dependency.
        
    Returns:
        dict: Dictionary containing access_token.
        
    Raises:
        HTTPException: If email or password is incorrect.
    """
    user_db = await get_user_by_email(user.email, db)
    verify = await run_in_threadpool(verify_password, user.password, user_db.password)

    if not user_db or not verify:
        return HTTPException(status_code=400, detail="Email or Password is wrong!")

    access = create_access_token(data={"sub": user_db[0]})
    jti = str(uuid.uuid4())
    refresh = await create_refresh_token(data={"sub": user_db[0]}, redis=r, user_id=user_db.id, jti=jti)

    response.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age= 60 * 60
    )
    return {"access_token": access}

@app.post("/auth/access")
async def access_token(request: Request, r: redis.Redis = Depends(get_redis)):
    """Generate a new access token using refresh token.
    
    Validates the refresh token from cookies and issues a new access token.
    
    Args:
        request: FastAPI Request object to access cookies.
        r: Redis client dependency.
        
    Returns:
        dict: Dictionary containing new access_token.
        
    Raises:
        HTTPException: If refresh token doesn't exist or is expired/invalid.
    """
    refresh = request.cookies.get("refresh_token")
    if not refresh:
        return HTTPException(status_code=400, detail="token doesnt exists or expired")
    user_id = await verify_token(refresh, "refresh", r)
    access = create_access_token(data={"sub": user_id})

    return {"access_token": access}

@app.post("/auth/logout")
async def logout(request: Request, response: Response, r: redis.Redis = Depends(get_redis)):
    """Logout user by invalidating refresh token.
    
    Deletes the refresh token from Redis and removes the cookie from response.
    
    Args:
        request: FastAPI Request object to access cookies.
        response: FastAPI Response object for deleting cookies.
        r: Redis client dependency.
        
    Returns:
        str: Success message indicating logout was successful.
    """
    refresh = request.cookies.get("refresh_token")
    if refresh:
        payload = await verify_token(refresh, "refresh", r)
        redis_key = payload[1]
        await r.delete(redis_key)
        response.delete_cookie(
            key="refresh_token",
            httponly=True,
            secure=True,
            samesite="lax",
        )
    return "logout successfully"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/access")

async def validate_user_token(token: str = Depends(oauth2_scheme), r : redis.Redis = Depends(get_redis)):
    """Validate JWT access token and return user ID.
    
    Dependency function for protecting endpoints that require authentication.
    
    Args:
        token: JWT access token from Authorization header.
        r: Redis client dependency.
        
    Returns:
        str: User ID extracted from the token payload.
        
    Raises:
        HTTPException: If token is invalid, expired, or missing.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Couldn't validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = await verify_token(token, "access", r)
        if not payload:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception

class CreateOrg(BaseModel):
    name : str

@app.post("/orgs")
async def create_org(org: CreateOrg, user = Depends(validate_user_token), db : AsyncSession = Depends(get_db)) :
    """Create a new organization and assign creator as owner.
    
    Args:
        org: CreateOrg model containing organization name.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Dictionary containing org_name and user_id.
    """
    new_org = models.Organizations(name=org.name)

    db.add(new_org)
    await db.commit()
    await db.refresh(new_org)

    member = models.UserOrgMemberships(user_id=user, org_id=org.id, role="owner")

    db.add(member)
    await db.commit()
    await db.refresh(member)

    return {
        "org_name": org.name,
        "user_id": user,
    }

@app.get("/orgs/{org_id}/members")
async def get_org(org_id: int, user = Depends(validate_user_token), db : AsyncSession = Depends(get_db)):
    """Get all members of an organization with their roles.
    
    Args:
        org_id: ID of the organization.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Dictionary mapping usernames to their role values.
    """
    stmt = (
        select(models.User.username, models.UserOrgMemberships.role)
        .join(models.User, models.User.id == models.UserOrgMemberships.user_id)
        .where(models.UserOrgMemberships.org_id == org_id)
    )
    result = await db.execute(stmt)
    rows = result.all()
    members = {username: role.value for username, role in rows}
    return members

class Member(BaseModel):
    email: EmailStr
    role: str

@app.post("orgs/{org_id}/invite")
async def invite_member(org_id: int, member: Member, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Invite a user to join an organization.
    
    Only owners and admins can invite new members.
    
    Args:
        org_id: ID of the organization.
        member: Member model containing email and role.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        str: Success message indicating user was added.
        
    Raises:
        HTTPException: If organization doesn't exist, user lacks permission,
                      or target user doesn't exist.
    """
    result = await db.execute(select(models.Organizations).where(models.Organizations.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=400, detail="organization doesn't exists")
    requester_role_result = await db.execute(select(models.UserOrgMemberships.role).where
                         (models.UserOrgMemberships.org_id == org.id,
                          models.UserOrgMemberships.user_id == user))

    requester_role = requester_role_result.scalar_one_or_none()

    if requester_role not in [models.OrgRole.owner, models.OrgRole.admin]:
        raise HTTPException(status_code=403, detail="Role not high enough to invite another member")
    target_user = await get_user_by_email(member.email, db)
    if not target_user:
        raise HTTPException(status_code=400, detail="target user doesn't exists")

    new_member = models.UserOrgMemberships(user_id=target_user.id, org_id=org.id, role=member.role)
    db.add(new_member)
    await db.commit()
    await db.refresh(new_member)

    return "User added successfully"

class UpdateRole(BaseModel):
    new_role: str

@app.patch("/orgs/{org_id}/members/{user_id}")
async def change_role(org_id: int, user_id: int, new_role: UpdateRole, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Update a member's role in an organization.
    
    Only owners and admins can change roles. Owners cannot be demoted.
    
    Args:
        org_id: ID of the organization.
        user_id: ID of the user whose role will be changed.
        new_role: UpdateRole model containing the new role.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        str: Success message indicating role was changed.
        
    Raises:
        HTTPException: If user lacks permission, target is owner, user tries
                      to change own role, or user is not a member.
    """
    requester_role_result = await db.execute(select(models.UserOrgMemberships.role).where
                                (models.UserOrgMemberships.org_id == org_id,
                                 models.UserOrgMemberships.user_id == user))
    requester_role = requester_role_result.scalar_one_or_none()
    if requester_role not in [models.OrgRole.owner, models.OrgRole.admin]:
        raise HTTPException(status_code=403, detail="Role not high enough to change someone else role")

    target_user_result = await db.execute(select(models.UserOrgMemberships).where
                                (models.UserOrgMemberships.org_id == org_id,
                                 models.UserOrgMemberships.user_id == user_id))
    target_user = target_user_result.scalar_one_or_none()
    if target_user.role == models.OrgRole.owner:
        raise HTTPException(status_code=400, detail="User is already owner and can not be changed")

    if user_id == user and target_user.role != requester_role:
        raise HTTPException(status_code=403, detail="Cannot change your own role")

    if not target_user:
        raise HTTPException(status_code=404, detail="User is not a member of this organization")

    target_user.role = OrgRole(new_role.new_role)
    await db.commit()
    await db.refresh(target_user)

    return "role changed successfully"

class Channel(BaseModel):
    provider : Providers
    display_name : str


@app.post("/orgs/{org_id}/channels/oauth")
async def create_channel(org_id: int, channel: Channel, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Create a new channel and initiate OAuth flow.
    
    Only owners and admins can create channels. Returns OAuth URL for authentication.
    
    Args:
        org_id: ID of the organization.
        channel: Channel model containing provider and display_name.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Dictionary containing OAuth URL for channel authentication.
        
    Raises:
        HTTPException: If user lacks permission to create channels.
    """
    user_role_result = await db.execute(select(models.UserOrgMemberships.role).where(models.UserOrgMemberships.user_id == user))
    user_role = user_role_result.scalar_one_or_none()
    if user_role not in [OrgRole.owner, OrgRole.admin]:
        raise HTTPException(status_code=403, detail="not enough permission to connect a channel")

    new_channel = models.Channels(org_id=org_id, provider=channel.provider, display_name=channel.display_name, is_active=False)

    db.add(new_channel)
    await db.commit()
    await db.refresh(new_channel)

    fake_oauth_url ="fake_oauth_url"

    return {fake_oauth_url: fake_oauth_url}

@app.post("/orgs/{org_id}/channels/{channel_id}/oauth/callback")
async def oauth_callback(org_id: int, channel_id: int, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Handle OAuth callback and activate channel.
    
    Processes OAuth callback, stores tokens, and marks channel as active.
    
    Args:
        org_id: ID of the organization.
        channel_id: ID of the channel.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        str: Success message indicating channel was connected.
        
    Raises:
        HTTPException: If channel doesn't exist.
    """
    channel_result = await db.execute(select(models.Channels).where(models.Channels.org_id == org_id,
                                                       models.Channels.id == channel_id))
    channel = channel_result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=400, detail="such channel doesnt exists")

    channel.access_token_enc = "fake_access_token"
    channel.refresh_token_enc = "fake_refresh_token"

    channel.is_active = True

    await db.commit()
    await db.refresh(channel)

    return "Channel connected successfully"

class ChannelBase(BaseModel):
    id: int
    org_id: int
    provider: str
    display_name: str
    created_at: str
    is_active: bool

    class Config:
        from_attributes = True

@app.get("/orgs/{org_id}/channels", response_model=list[ChannelBase])
async def get_channels(org_id: int, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Get all channels for an organization.
    
    Args:
        org_id: ID of the organization.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        list[ChannelBase]: List of channel objects for the organization.
    """
    channels_result = await db.execute(select(models.Channels).filter_by(org_id=org_id))
    channels = channels_result.all()
    return channels

@app.delete("/channels/{channel_id}")
async def delete_channel(channel_id: str, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Delete a channel.
    
    Only owners and admins can delete channels.
    
    Args:
        channel_id: ID of the channel to delete.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Success message indicating channel was deleted.
        
    Raises:
        HTTPException: If user lacks permission or channel doesn't exist.
    """
    user_role_result = await db.execute(select(models.UserOrgMemberships.role).where(
        models.UserOrgMemberships.user_id == user))
    user_role = user_role_result.scalar_one_or_none()


    if user_role not in [OrgRole.owner, OrgRole.admin]:
        raise HTTPException(status_code=403, detail="not enough permission to delete a channel")

    channel_result = await db.execute(select(models.Channels).where(models.Channels.id == channel_id))
    channel = channel_result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=400, detail="channel doesn't exists")

    await db.delete(channel)
    await db.commit()

    return {"message": "Channel deleted successfully"}

class Post(BaseModel):
    channel_id: int
    body_text: str
    media_url: str
    scheduled_at: datetime
    status : StatusPosts # queue or draft


@app.post("/orgs/{org_id}/posts")
async def create_post(org_id: int, post: Post, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Create a new scheduled post.
    
    Creates a post and schedules it for publication. Editors require approval,
    while owners and admins don't. Schedules a Celery task for publication.
    
    Args:
        org_id: ID of the organization.
        post: Post model containing channel_id, body_text, media_url, scheduled_at, and status.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Success message indicating post was scheduled.
        
    Raises:
        HTTPException: If user is a viewer (cannot create posts).
    """
    user_role_result = await db.execute(select(models.UserOrgMemberships.role).
                           where(models.UserOrgMemberships.user_id == user))
    user_role = user_role_result.scalar_one_or_none()
    if user_role == OrgRole.viewer:
        raise HTTPException(status_code=400, detail="Viewer can not create post")

    if user_role in [OrgRole.owner, OrgRole.admin]:
        approvals_required = False

    else: approvals_required = True

    new_post = models.Posts(org_id=org_id, channel_id=post.channel_id, author_user_id=user,
                            body_text=post.body_text, media_url=post.media_url, scheduled_at=post.scheduled_at,
                            approvals_required=approvals_required, status=post.status)

    db.add(new_post)
    await db.commit()
    await db.refresh(new_post)

    task = await publish_post.apply_async(args=[new_post.id], eta=post.scheduled_at)

    new_post.celery_task_id = task.id
    await db.commit()
    await db.refresh(new_post)

    return {"message": "post scheduled"}


@app.get("/orgs/{org_id}/posts")
async def post_list(
    org_id: int,
    channel_id: int,
    status: Optional[StatusPosts] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user = Depends(validate_user_token)
):
    # Validate org exists
    org_result = await db.execute(
        select(models.Organizations).where(models.Organizations.id == org_id)
    )
    org = org_result.scalar_one_or_none()

    if not org:
        raise HTTPException(status_code=400, detail="Organization does not exist")

    # Base query
    stmt = select(models.Posts).where(models.Posts.channel_id == channel_id)

    # Filter by status
    if status:
        stmt = stmt.where(models.Posts.status == status)

    # Sorting
    if sort:
        if sort.startswith("-"):
            field_name = sort[1:]
            stmt = stmt.order_by(desc(getattr(models.Posts, field_name)))
        else:
            stmt = stmt.order_by(asc(getattr(models.Posts, sort)))

    # Pagination
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    # Fetch paginated posts
    posts_result = await db.execute(stmt)
    posts = posts_result.scalars().all()

    # Count total
    count_stmt = select(func.count()).select_from(models.Posts).where(
        models.Posts.channel_id == channel_id
    )
    if status:
        count_stmt = count_stmt.where(models.Posts.status == status)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar()

    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "posts": posts
    }


class Update(BaseModel):
    body: Optional[str] = None
    media: Optional[str] = None
    status: Optional[StatusPosts] = None

@app.post("/posts/{post_id}")
async def edit_post(post_id: int, update: Update, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Update an existing post.
    
    Allows updating body text, media URL, and status. Cannot edit published or publishing posts.
    Viewers cannot edit posts.
    
    Args:
        post_id: ID of the post to update.
        update: Update model containing optional body, media, and status fields.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Success message indicating post was updated.
        
    Raises:
        HTTPException: If user is a viewer, or post is already published/publishing.
    """
    post_result = await db.execute(select(models.Posts).where(models.Posts.id == post_id))
    post = post_result.scalar_one_or_none()
    _user_result = await db.execute(select(models.UserOrgMemberships)
                       .where(models.UserOrgMemberships.org_id == post.org_id,
                              models.UserOrgMemberships.user_id == user))
    _user = _user_result.scalar_one_or_none()
    if _user.role == OrgRole.viewer:
        raise HTTPException(status_code=403, detail="user not allowed to edit posts")
    if post.status in [StatusPosts.published, StatusPosts.publishing]:
        raise HTTPException(status_code=400, detail="post already published or is being published")
    if update.body:
        post.body_text = update.body
    if update.media:
        post.media_url = update.media
    if update.status:
        post.status = update.status
    post.updated_at = func.now()
    await db.commit()

    return {"message": "Post updated successfully"}

@app.post("/posts/{post_id}/approve")
async def approve_post(post_id: int, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Approve a post that requires approval.
    
    Only owners and admins can approve posts. If post is already approved, returns early.
    
    Args:
        post_id: ID of the post to approve.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        str: Success message indicating post was approved, or message if already approved.
        
    Raises:
        HTTPException: If user lacks permission to approve posts.
    """
    post_result = await db.execute(select(models.Posts).where(models.Posts.id == post_id))
    post = post_result.scalar_one_or_none()
    _user_result = await db.execute(select(models.UserOrgMemberships)
                       .where(models.UserOrgMemberships.org_id == post.org_id,
                              models.UserOrgMemberships.user_id == user))
    _user = _user_result.scalar_one_or_none()

    if _user.role not in [OrgRole.owner, OrgRole.admin]:
        raise HTTPException(status_code=403, detail="User not allowed to approve this post")
    post_approval_result = await db.execute(select(models.PostApprovals).where(
        models.PostApprovals.post_id == post_id))
    post_approval = post_approval_result.scalar_one_or_none()
    if post_approval:
        return "this post is already approved"
    post_approval = models.PostApprovals(post_id=post_id, approver_user_id=user)
    db.add(post_approval)
    await db.commit()
    await db.refresh(post_approval)

    return "post successfully approved"


@app.post("/posts/{post_id}/cancel")
async def cancel_post(post_id: int, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Cancel a scheduled post.
    
    Revokes the Celery task and marks the post as canceled. Only owners and admins can cancel posts.
    
    Args:
        post_id: ID of the post to cancel.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Success message indicating post was canceled.
        
    Raises:
        HTTPException: If user lacks permission to cancel posts.
    """
    post_result = await db.execute(select(models.Posts).where(models.Posts.id == post_id))
    post = post_result.scalar_one_or_none()
    _user_result = await db.execute(select(models.UserOrgMemberships)
                       .where(models.UserOrgMemberships.org_id == post.org_id,
                              models.UserOrgMemberships.user_id == user))
    _user = _user_result.scalar_one_or_none()

    if _user.role not in [OrgRole.owner, OrgRole.admin]:
        raise HTTPException(status_code=403, detail="User not allowed to cancel this post")

    task_id = post.celery_task_id

    celery_app.control.revoke(task_id, terminate=True)

    post.status = StatusPosts.canceled
    await db.commit()

    return {"message": "Post canceled successfully"}

@app.post("/posts/{post_id}/publish")
async def publish_now(post_id: int, user = Depends(validate_user_token), db: AsyncSession = Depends(get_db)):
    """Publish a post immediately.
    
    Bypasses the scheduled time and publishes the post right away.
    Only owners and admins can publish posts.
    
    Args:
        post_id: ID of the post to publish.
        user: Authenticated user ID from token validation.
        db: Database session dependency.
        
    Returns:
        dict: Success message indicating post was published.
        
    Raises:
        HTTPException: If user lacks permission to publish posts.
    """
    post_result = await db.execute(select(models.Posts).where(models.Posts.id == post_id))
    post = post_result.scalar_one_or_none()
    _user_result = await db.execute(select(models.UserOrgMemberships)
                       .where(models.UserOrgMemberships.org_id == post.org_id,
                              models.UserOrgMemberships.user_id == user))
    _user = _user_result.scalar_one_or_none()

    if _user.role not in [OrgRole.owner, OrgRole.admin]:
        raise HTTPException(status_code=403, detail="User not allowed to publish this post")

    # mock publish now

    post.status = StatusPosts.published
    await db.commit()

    return {"message": "Post published successfully"}
