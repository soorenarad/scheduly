from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from setting import settings

engine = create_async_engine(settings.DB_UR, echo=True)

AsyncSessionLocal = sessionmaker(
    engine,               # bind the engine here
    expire_on_commit=False,
    class_=AsyncSession,  # tell sessionmaker to produce AsyncSession instances
    autoflush=False,      # optional
)

Base = declarative_base()
