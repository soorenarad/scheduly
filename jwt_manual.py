from datetime import datetime, timedelta
from jose import jwt, JWTError
from redis import Redis
SECRET_KEY_ACCESS = "Very_Nice_Access_token"
SECRET_KEY_REFRESH = "Very_Nice_Refresh_token"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict) -> str:
    """Create a signed JWT containing `data` and an expiry (exp)."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    to_encode.update({"type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_ACCESS, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, redis: Redis, user_id, jti):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    to_encode.update({"type": "refresh"})
    to_encode.update({"jti": jti})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_REFRESH, algorithm=ALGORITHM)
    redis_key = f"refresh:{user_id}:{jti}"
    ttl = int((expire - datetime.utcnow()).total_seconds())
    redis.setex(redis_key, ttl, encoded_jwt)
    return encoded_jwt

def verify_token(token: str, token_type: str, redis: Redis):
    try:
        secret_key = SECRET_KEY_ACCESS if token_type.lower() == "access" else SECRET_KEY_REFRESH
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        if payload.get("type") != token_type.lower():
            raise JWTError("Invalid token type")
        user_id = payload.get("sub")
        jti = payload.get("jti")
        if not user_id:
            raise JWTError("Token not found or revoked")
        if token_type == "refresh":
            redis_key = f"refresh:{user_id}:{jti}"
            stored_token = redis.get(redis_key)
            if not stored_token or stored_token.decode() != token:
                raise JWTError("Token not found or revoked")
            return user_id, redis_key
        return user_id
    except JWTError:
        return "Failed to validate the token"

