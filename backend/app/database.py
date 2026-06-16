import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, TypeDecorator
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Configurable database URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

# Setup Engine
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

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
