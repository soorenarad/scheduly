from sqlalchemy.orm import Session
import models
from sqlalchemy import select
from passlib.context import CryptContext
from fastapi import HTTPException
from pydantic import EmailStr

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_user(db: Session, username: str, email: EmailStr, password: str, role: str):
    exists_username = db.execute(select(models.User).where(models.User.username == username))
    if exists_username:
        raise HTTPException(status_code=401, detail="Username already exists")
    exists_email = db.execute(select(models.User).where(models.User.email == email))
    if exists_email:
        raise HTTPException(status_code=401, detail="Email already exists")

    hashed_password = hash_password(password)

    user = models.User(username=username, email=email, password=hashed_password)
    db.add(user)

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Failed to create the user")

    db.refresh(user)
    return user

def get_user_by_email(email: EmailStr, db: Session):
    user = db.execute(select(models.User).where(models.User.email == email)).scalar_one_or_none()
    if user:
        return user
    else: return False