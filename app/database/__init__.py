"""Storage. SQLite file by default; PostgreSQL via DATABASE_URL=postgresql+psycopg2://user:pass@host/db.
ponytail: create_all only creates missing tables; add Alembic migrations before changing columns on a live database."""
import os
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA = Path(__file__).resolve().parents[2] / "data"
URL = os.environ.get("DATABASE_URL", f"sqlite:///{(DATA / 'androguard.db').as_posix()}")
if URL.startswith("sqlite"):
    DATA.mkdir(exist_ok=True)
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {})
Session = sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(254), unique=True, nullable=False)
    name = Column(String(80), default="")
    password_hash = Column(String(200), nullable=False)
    role = Column(String(16), nullable=False, default="user")  # user | admin | superadmin
    status = Column(String(16), nullable=False, default="active")  # active | blocked
    scan_limit = Column(Integer)  # None = unlimited
    notes = Column(Text, default="")  # CRM notes, visible to admins only
    created_at = Column(DateTime(timezone=True), default=now)
    last_login_at = Column(DateTime(timezone=True))


class AuthSession(Base):
    __tablename__ = "sessions"
    token_hash = Column(String(64), primary_key=True)  # sha256 of the cookie value: a DB leak exposes no tokens
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    sha256 = Column(String(64))
    status = Column(String(16), nullable=False, default="queued")  # queued | running | done | failed
    progress = Column(String(255), default="")
    error = Column(Text)
    report = Column(JSON)  # findings, risk and metadata only: the package itself is never stored
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # None = free trial scan
    device_id = Column(String(64), index=True)  # browser that uploaded it (free-trial quota and ownership)
    created_at = Column(DateTime(timezone=True), default=now)
    finished_at = Column(DateTime(timezone=True))


Base.metadata.create_all(engine)
