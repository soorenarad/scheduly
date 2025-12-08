from celery_app import celery_app
from db import AsyncSessionLocal
import models

@celery_app.task
async def publish_post(post_id: int):
    """Celery task to publish a scheduled post.
    
    Checks if the post requires approval and if it's been approved.
    Publishes the post to the associated channel and updates its status.
    
    Args:
        post_id: ID of the post to publish.
        
    Returns:
        str: Status message ("Published", "Post not found", or "Post not approved yet").
        
    Raises:
        Exception: If publishing fails, the exception is raised and post status
                  is set to "failed" with error message stored.
    """
    db = AsyncSessionLocal()

    post_result = await db.query(models.Posts).filter(models.Posts.id == post_id)
    post = post_result.first()
    if not post:
        return "Post not found"

    post_approved_result = await db.query(models.PostApprovals.approved_at).filter(models.PostApprovals.post_id == post_id)
    post_approved = post_approved_result.first()
    if post.approvals_required and post_approved is None:
        return "Post not approved yet"

    try:
        print(f"Publishing post {post.id} to channel {post.channel_id}")

        post.status = models.StatusPosts.published
        await db.commit()
        return "Published"

    except Exception as e:
        post.status = "failed"
        post.last_error = e
        await db.commit()

        raise e
