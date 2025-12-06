from sqlalchemy import (Column, Integer, String, ForeignKey, Boolean, func, Enum, DateTime, UniqueConstraint, DateTime,
                        JSON)
from sqlalchemy.orm import relationship
from db import Base
import enum

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, index=True, nullable=False)
    username = Column(String, index=True, nullable=False)


class Organizations(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class OrgRole(enum.Enum):
    owner = "owner"
    admin = "admin"
    editor = "editor"
    viewer = "viewer"

class UserOrgMemberships(Base):
    __tablename__ = "memberships"
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(Enum(OrgRole, name="org_role_enum"), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_user_org_membership"),
    )


class Providers(enum.Enum):
    twt = "twt"
    insta = "insta"

class Channels(Base):
    __tablename__ = "channels"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(Enum(Providers, name="provider_enum"), nullable=False)
    display_name = Column(String, index=True, nullable=False)
    access_token_enc = Column(String, nullable=True)
    refresh_token_enc = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_active = Column(Boolean, default=False, index=True)


class StatusPosts(enum.Enum):
    draft = "draft"
    queued = "queued"
    publishing = "publishing"
    published = "published"
    failed = "failed"
    canceled = "canceled"

class Posts(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    channel_id = Column(ForeignKey("channels.id", ondelete="CASCADE"), nullable=False, index=True)
    author_user_id = Column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    body_text = Column(String, nullable=True)
    media_url = Column(String, nullable=False)
    status = Column(Enum(StatusPosts), nullable=False, index=True)
    scheduled_at = Column(DateTime(timezone=True), index=True, nullable=False)
    published_at = Column(DateTime(timezone=True), index=True, nullable=True)
    last_error = Column(String , nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), index=True, nullable=True)
    approvals_required = Column(Boolean, index=True, nullable=False, default=False)
    celery_task_id = Column(String, nullable=True)

class PostApprovals(Base):
    __tablename__ = "approvals"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(ForeignKey("posts.id"), nullable=False, index=True)
    approver_user_id = Column(ForeignKey("users.id"), nullable=False, index=True)
    approved_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class StatusOutBox(enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    succeeded = "succeeded"
    failed = "failed"

class OutBox(Base):
    __tablename__ = "outbox"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(ForeignKey("posts.id", ondelete="CASCADE"), nullable=False, index=True)
    attempt_no = Column(Integer, default=0)
    payload_json = Column(JSON, nullable=True)
    due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    locked_by = Column(String, nullable=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(Enum(StatusOutBox), nullable=False, index=True)
    error = Column(String, nullable=True)

# webhook_events (id, provider, external_id, payload_json, signature,
# received_at, processed_at, status ENUM[pending, processed,
# duplicate, failed))

# class WebhookEvents(Base):
#     pass


class ApiKeys(Base):
    __tablename__ = "apikey"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, unique=True, nullable=False)
    key_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    active = Column(Boolean, default=True)


class RefreshToken(Base):
    __tablename__ = "refresh"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
