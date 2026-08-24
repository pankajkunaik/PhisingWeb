import os
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, TypeDecorator, event
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

logger = logging.getLogger("phishguard.db")

# ── Database URL ───────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

# Neon (and Heroku) provides postgres:// but SQLAlchemy 2.x requires postgresql://
# Also ensure we use the psycopg2 dialect for synchronous access
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# ── Engine ─────────────────────────────────────────────────────────────────────
_is_sqlite = DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    # PostgreSQL / Neon — SSL required, robust keepalive & recycling for serverless PgBouncer
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=5,
        pool_timeout=30,
        pool_recycle=60,          # Recycle connections every 60s to prevent stale serverless connections
        pool_pre_ping=True,        # Reconnect automatically after idle pause
        connect_args={
            "sslmode": "require",  # Neon mandates SSL
            "connect_timeout": 15,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    )
    logger.info("🐘 Using PostgreSQL (Neon) database")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Custom JSON Type Decorator for SQLite/Postgres compatibility
class JSONSerializedType(TypeDecorator):
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return {}

# Database Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Integer, default=1)  # 1 for active, 0 for inactive
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scans = relationship("ScanRecord", back_populates="user", cascade="all, delete-orphan")
    watchlist = relationship("WatchlistDomain", back_populates="user", cascade="all, delete-orphan")

class WatchlistDomain(Base):
    __tablename__ = "watchlist_domains"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    label = Column(String(255), nullable=True)
    status = Column(String(50), default="Active")  # Active, Warning, Critical
    ssl_valid = Column(Integer, default=1)
    ssl_days_left = Column(Integer, default=365)
    risk_score = Column(Float, default=0.0)
    last_checked = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="watchlist")

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    url = Column(String(2048), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)  # 0 to 100
    prediction = Column(String(50), nullable=False)  # Safe, Suspicious, Phishing
    
    # Telemetry and diagnosis details
    lexical_features = Column(JSONSerializedType, nullable=True)
    html_features = Column(JSONSerializedType, nullable=True)
    whois_info = Column(JSONSerializedType, nullable=True)
    ssl_info = Column(JSONSerializedType, nullable=True)
    dns_info = Column(JSONSerializedType, nullable=True)
    threat_feeds = Column(JSONSerializedType, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="scans")

def get_db():
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes tables in the database."""
    Base.metadata.create_all(bind=engine)
