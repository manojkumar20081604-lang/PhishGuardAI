"""
Model Versioning Service - Track and manage ML model versions.
Enables reproducibility, rollback, and A/B testing of models.
"""

import os
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from models import ModelVersion


class ModelVersionService:
    """Manages ML model versioning."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def register_version(self, version_name: str, model_type: str, 
                        model_path: str, accuracy: float = None,
                        precision: float = None, recall: float = None,
                        f1_score: float = None, xai_enabled: bool = False):
        """Register a new model version."""
        
        # Check if this is replacing an active version
        existing_active = ModelVersion.query.filter_by(
            model_type=model_type,
            is_active=True
        ).first()
        
        replaced_version = None
        if existing_active:
            print(f"🔄 Replacing active version: {existing_active.version_name}")
            replaced_version = existing_active.version_name
        
        # Create new version record
        new_version = ModelVersion(
            version_name=version_name,
            model_type=model_type,
            model_path=model_path,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            xai_enabled=xai_enabled,
            replaced_version=replaced_version,
            is_active=True,
            deployment_date=datetime.utcnow()
        )
        
        self.db.add(new_version)
        self.db.commit()
        
        print(f"✓ Registered model version: {version_name}")
        print(f"  Type: {model_type}, Path: {model_path}")
        if accuracy:
            print(f"  Accuracy: {accuracy:.4f}")
        
        return new_version
    
    def activate_version(self, version_name: str):
        """Activate a specific model version."""
        version = ModelVersion.query.filter_by(version_name=version_name).first()
        
        if not version:
            raise ValueError(f"Model version '{version_name}' not found")
        
        # Deactivate all versions of same type
        existing_active = ModelVersion.query.filter_by(
            model_type=version.model_type,
            is_active=True
        ).first()
        
        if existing_active and existing_active.version_name != version_name:
            print(f"⚠️  Deactivating previous active: {existing_active.version_name}")
            existing_active.is_active = False
        
        # Activate new version
        version.is_active = True
        self.db.commit()
        
        print(f"✓ Activated model version: {version_name}")
    
    def get_latest_version(self, model_type: str) -> Optional[ModelVersion]:
        """Get the latest active version of a model type."""
        return ModelVersion.query.filter_by(
            model_type=model_type,
            is_active=True
        ).order_by(ModelVersion.created_at.desc()).first()
    
    def get_all_versions(self, model_type: str = None) -> list:
        """Get all versions (with optional filter by type)."""
        if model_type:
            return ModelVersion.query.filter_by(model_type=model_type).all()
        return ModelVersion.query.all()


# Global instance
_model_version_service = None

def get_version_service(db: Session):
    """Get or create global version service instance."""
    global _model_version_service
    if _model_version_service is None:
        _model_version_service = ModelVersionService(db)
    return _model_version_service
