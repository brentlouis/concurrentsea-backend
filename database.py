import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

load_dotenv()

engine = create_engine(
    os.getenv("DATABASE_URL"),
    pool_size=10,
    max_overflow=5,
    pool_pre_ping=True,
)