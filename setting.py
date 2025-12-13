from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DB_URL: str
    Redis_host: str
    Redis_port: int
    SECRET_KEY_ACCESS: str
    SECRET_KEY_REFRESH: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int

    class Config:
        env_file = ".env"

settings = Settings()