from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from components.config import DB_CONNECTION_STRING

# SQLite specific args if it's sqlite
connect_args = {"check_same_thread": False} if DB_CONNECTION_STRING.startswith("sqlite") else {}

engine = create_engine(
    DB_CONNECTION_STRING, connect_args=connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
