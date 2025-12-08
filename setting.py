from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DB_URL: str
    Redis_host: str
    Redis_port: int

    class Config:
        env_file = ".env"

settings = Settings()