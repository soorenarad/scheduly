from sqlalchemy.ext.asyncio import AsyncSession
import models
from sqlalchemy import select
from passlib.context import CryptContext
from fastapi import HTTPException
from pydantic import EmailStr

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str):
    """Hash a plain text password using pbkdf2_sha256.
    
    Args:
        password: Plain text password to hash.
        
    Returns:
        str: Hashed password string.
    """
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Verify a plain text password against a hashed password.
    
    Args:
        plain_password: Plain text password to verify.
        hashed_password: Hashed password to compare against.
        
    Returns:
        bool: True if passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

async def create_user(db: AsyncSession, username: str, email: EmailStr, password: str):
    """Create a new user in the database.
    
    Validates that username and email are unique, hashes the password,
    and creates the user record.
    
    Args:
        db: Database session.
        username: Unique username for the user.
        email: Unique email address for the user.
        password: Plain text password (will be hashed).
        
    Returns:
        models.User: The created user object.
        
    Raises:
        HTTPException: If username or email already exists, or if user creation fails.
    """
    exists_username_result  = await db.execute(select(models.User).where(models.User.username == username))
    exists_username = exists_username_result.scalar_one_or_none()
    if exists_username:
        raise HTTPException(status_code=401, detail="Username already exists")
    exists_email_result = await db.execute(select(models.User).where(models.User.email == email))
    exists_email = exists_email_result.scalar_one_or_none()
    if exists_email:
        raise HTTPException(status_code=401, detail="Email already exists")

    hashed_password = hash_password(password)

    user = models.User(username=username, email=email, password=hashed_password)

    db.add(user)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Failed to create the user")

    await db.refresh(user)
    return user

async def get_user_by_email(email: EmailStr, db: AsyncSession):
    """Retrieve a user by their email address.
    
    Args:
        email: Email address to search for.
        db: Database session.
        
    Returns:
        models.User: User object if found, False otherwise.
    """
    result = await db.execute(select(models.User).where(models.User.email == email))
    user = result.scalar_one_or_none()
    if user:
        return user
    else: return False