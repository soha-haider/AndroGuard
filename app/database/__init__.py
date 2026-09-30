"""Scan storage. SQLite file by default; PostgreSQL via DATABASE_URL=postgresql+psycopg2://user:pass@host/db."""
import os
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import JSON, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA = Path(__file__).resolve().parents[2] / "data"
URL = os.environ.get("DATABASE_URL", f"sqlite:///{(DATA / 'androguard.db').as_posix()}")
if URL.startswith("sqlite"):
    DATA.mkdir(exist_ok=True)
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {})
Session = sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    sha256 = Column(String(64))
    status = Column(String(16), nullable=False, default="queued")  # queued | running | done | failed
    progress = Column(String(255), default="")
    error = Column(Text)
    report = Column(JSON)  # findings, risk and metadata only: the package itself is never stored
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True))


Base.metadata.create_all(engine)
