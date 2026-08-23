"""
Database models for PhishGuardAI - User accounts, scan history, threat intel cache, model versioning.
Uses SQLAlchemy ORM with SQLite (dev) / PostgreSQL (prod).
"""

from datetime import datetime
from enum import Enum
import uuid
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, Table, JSON
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class _QueryProperty:
    """Flask-SQLAlchemy style Model.query backed by the shared scoped session."""

    def __get__(self, obj, cls):
        from database import ScopedSession
        return ScopedSession().query(cls)


Base.query = _QueryProperty()


class User(Base):
    """User account model for multi-tenant deployment."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    hashed_password = Column(String(256))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    scan_history = relationship("ScanHistory", back_populates="user")
    feedback_entries = relationship("FeedbackEntry", back_populates="user")


class ScanType(Enum):
    URL = "url"
    EMAIL = "email"
    TEXT = "text"
    MIXED = "mixed"


class RiskLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ScanHistory(Base):
    """Complete scan history with results and metadata."""
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    session_id = Column(String(64), default=lambda: str(uuid.uuid4())[:32])
    scan_type = Column(SAEnum(ScanType), nullable=False)
    
    # Input data (stored as JSON for flexibility)
    input_url = Column(Text, nullable=True)
    input_email = Column(Text, nullable=True)
    input_text = Column(Text, nullable=True)
    input_data_json = Column(JSON, nullable=True)  # Fallback for mixed types
    
    # Results
    risk_score = Column(Float, default=0.5)
    risk_level = Column(SAEnum(RiskLevel), default=RiskLevel.MEDIUM)
    
    # Feature extraction results (JSON for ML model outputs)
    features_json = Column(JSON, nullable=True)
    
    # Model info
    model_version = Column(String(64))
    model_name = Column(String(128))
    
    # XAI explanations
    explanation_text = Column(Text)
    feature_importance_json = Column(JSON)
    
    # Sandbox results (if applicable)
    sandbox_results_json = Column(JSON, nullable=True)
    
    # User feedback
    user_feedback = Column(Integer, nullable=True)  # -1: no feedback, 0-5: confidence
    feedback_text = Column(Text, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=func.now())
    
    user = relationship("User", back_populates="scan_history")


class ThreatIntelCache(Base):
    """Cached threat intelligence results to avoid redundant API calls."""
    __tablename__ = 'threat_intel_cache'
    
    id = Column(Integer, primary_key=True)
    cache_key = Column(String(256), unique=True, index=True)  # e.g., "vt:domain.com" or "phish:domain.com"
    
    # Source-specific results
    virustotal_data = Column(JSON, nullable=True)
    phishtank_data = Column(JSON, nullable=True)
    safebrowsing_data = Column(JSON, nullable=True)
    urlvoid_data = Column(JSON, nullable=True)
    other_sources_json = Column(JSON, nullable=True)  # For future sources
    
    # Aggregated results
    is_malicious = Column(Boolean, default=False)
    malicious_count = Column(Integer, default=0)
    total_sources_checked = Column(Integer, default=0)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # TTL-based expiration
    source_type = Column(String(64))  # "vt", "phish", "safebrowsing", etc.


class ModelVersion(Base):
    """Track ML model versions for reproducibility and rollback."""
    __tablename__ = 'model_versions'
    
    id = Column(Integer, primary_key=True)
    version_name = Column(String(128), unique=True, nullable=False)  # e.g., "ensemble_v1.0", "nlp_v2.3"
    
    model_type = Column(String(64))  # "ensemble", "nlp", "hybrid"
    model_path = Column(Text, nullable=False)  # Path to saved model file
    
    # Model metadata
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    
    training_data_version = Column(String(64))
    feature_set_version = Column(String(64))
    
    # XAI model info
    xai_enabled = Column(Boolean, default=False)
    xai_model_path = Column(Text, nullable=True)
    
    # Deployment info
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=False)  # Only one active per model_type
    deployment_date = Column(DateTime, nullable=True)
    
    # Rollback info
    replaced_version = Column(String(128), nullable=True)


class FeedbackEntry(Base):
    """User feedback for self-learning pipeline."""
    __tablename__ = 'feedback_entries'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Linked scan (optional - for retrospective feedback)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=True)
    
    # Feedback data
    scan_type = Column(SAEnum(ScanType), nullable=True)
    input_data_json = Column(JSON, nullable=True)  # The original input
    
    feedback_text = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.5)
    is_false_positive = Column(Boolean, default=False)
    
    # User metadata (optional context)
    user_context_json = Column(JSON, nullable=True)  # e.g., "was in email from trusted sender"
    
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="feedback_entries")


class DashboardMetrics(Base):
    """Aggregated metrics for dashboard (pre-computed for performance)."""
    __tablename__ = 'dashboard_metrics'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # NULL = global stats
    
    metric_type = Column(String(64))  # "accuracy", "precision", "recall", "f1"
    window_days = Column(Integer, default=7)  # Rolling window
    
    value = Column(Float, nullable=False)
    count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class SystemConfig(Base):
    """System-wide configuration stored in database."""
    __tablename__ = 'system_config'
    
    id = Column(Integer, primary_key=True)
    config_key = Column(String(128), unique=True, nullable=False)  # e.g., "vt_api_key", "phishtank_api_key"
    config_value = Column(Text, nullable=False)
    config_type = Column(String(64))  # "api_key", "boolean", "integer", "float", "json"
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=func.now())


# Many-to-Many: Users and Model Versions (for audit trail)
UserModelVersions = Table(
    'user_model_versions',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('version_id', Integer, ForeignKey('model_versions.id'), primary_key=True),
    Column('activated_at', DateTime, default=datetime.utcnow)
)


# Many-to-Many: Users and Feedback Entries (for audit trail)
UserFeedbackEntries = Table(
    'user_feedback_entries',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('entry_id', Integer, ForeignKey('feedback_entries.id'), primary_key=True),
    Column('reviewed_at', DateTime, default=datetime.utcnow)
)
