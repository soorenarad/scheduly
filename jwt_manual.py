from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

from jose import jwt, JWTError
from redis import Redis
from setting import settings

def create_access_token(data: dict) -> str:
    """Create a signed JWT access token containing user data and expiry.
    
    Args:
        data: Dictionary containing user information (typically {"sub": user_id}).
        
    Returns:
        str: Encoded JWT access token string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    to_encode.update({"type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY_ACCESS, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def create_refresh_token(data: dict, redis: Redis, user_id, jti):
    """Create a signed JWT refresh token and store it in Redis.
    
    Creates a refresh token with a unique JTI (JWT ID) and stores it in Redis
    for revocation tracking. The token is stored with a TTL matching its expiration.
    
    Args:
        data: Dictionary containing user information (typically {"sub": user_id}).
        redis: Redis client instance for storing the token.
        user_id: ID of the user the token belongs to.
        jti: Unique JWT ID (JTI) for token tracking.
        
    Returns:
        str: Encoded JWT refresh token string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    to_encode.update({"type": "refresh"})
    to_encode.update({"jti": jti})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY_REFRESH, algorithm=settings.ALGORITHM)
    redis_key = f"refresh:{user_id}:{jti}"
    ttl = int((expire - datetime.now(timezone.utc)).total_seconds())
    await redis.setex(redis_key, ttl, encoded_jwt)
    return encoded_jwt

async def verify_token(token: str, token_type: str, redis: Redis):
    """Verify and decode a JWT token.
    
    Validates the token signature, expiration, and type. For refresh tokens,
    also verifies the token exists in Redis (not revoked).
    
    Args:
        token: JWT token string to verify.
        token_type: Type of token ("access" or "refresh").
        redis: Redis client instance for checking refresh token validity.
        
    Returns:
        str or tuple: For access tokens, returns user_id. For refresh tokens,
                     returns (user_id, redis_key). Returns error string on failure.
    """
    try:
        secret_key = settings.SECRET_KEY_ACCESS if token_type.lower() == "access" else settings.SECRET_KEY_REFRESH
        payload = jwt.decode(token, secret_key, algorithms=[settings.ALGORITHM])
        if payload.get("type") != token_type.lower():
            raise JWTError("Invalid token type")
        user_id = payload.get("sub")
        jti = payload.get("jti")
        if not user_id:
            raise JWTError("Token not found or revoked")
        if token_type == "refresh":
            redis_key = f"refresh:{user_id}:{jti}"
            stored_token = await redis.get(redis_key)
            if not stored_token or stored_token.decode("utf-8") != token:
                raise JWTError("Token not found or revoked")
            return int(user_id), redis_key
        return int(user_id)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"verification failed {e}")

