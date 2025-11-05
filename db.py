from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from urllib.parse import quote_plus

password = "Fire123@"  # your actual password
encoded_password = quote_plus(password)  # URL-encode special characters

DATABASE_URL = f"postgresql://postgres:{encoded_password}@localhost:5432/fastapi_db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()




