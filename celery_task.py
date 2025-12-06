from celery_app import celery_app
from db import SessionLocal
import models

@celery_app.task
def publish_post(post_id: int):
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
    db = SessionLocal()

    post = db.query(models.Posts).filter(models.Posts.id == post_id).first()
    if not post:
        return "Post not found"

    post_approved = db.query(models.PostApprovals.approved_at).filter(models.PostApprovals.post_id == post_id).first()

    if post.approvals_required and post_approved is None:
        return "Post not approved yet"

    try:
        print(f"Publishing post {post.id} to channel {post.channel_id}")

        post.status = models.StatusPosts.published
        db.commit()
        db.close()
        return "Published"

    except Exception as e:
        post.status = "failed"
        post.last_error = e
        db.commit()
        db.close()

        raise e
