"""
Database initialization and session management for PhishGuardAI.
Supports SQLite (dev) / PostgreSQL (prod).
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from models import Base, User, ScanHistory, ThreatIntelCache, ModelVersion, FeedbackEntry, DashboardMetrics, SystemConfig


# Database URL configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./phishguard.db"  # Default: SQLite in project root
)

# Engine setup
engine = create_engine(
    DATABASE_URL.replace("sqlite:///", "sqlite:///"),
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Request-scoped session registry: Model.query and get_session() share
# the same session within a thread/context.
ScopedSession = scoped_session(SessionLocal)


def get_scoped_session():
    """Get the thread/context-local shared session."""
    return ScopedSession()


def get_db():
    """Get database session (use as dependency or context manager)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database(create_tables=True):
    """Initialize database - create tables if needed."""
    print(f"Initializing database at: {DATABASE_URL}")
    
    if create_tables:
        Base.metadata.create_all(bind=engine)
        print("✓ Database tables created")
    else:
        print("✓ Using existing database schema")


def drop_database():
    """Drop all tables (useful for testing)."""
    Base.metadata.drop_all(bind=engine)
    print("✓ All tables dropped")


# Initialize on import
init_database()
