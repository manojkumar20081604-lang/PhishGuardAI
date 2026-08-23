"""
Scan History Service - Store and retrieve complete scan results with metadata.
Enables audit trails, trend analysis, and user-specific dashboards.
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from models import ScanHistory, User, ScanType, RiskLevel


class ScanHistoryService:
    """Manages scan history storage and retrieval."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def save_scan_result(self, user_id: int, session_id: str, 
                        scan_type: ScanType, input_url: str = None,
                        input_email: str = None, input_text: str = None,
                        risk_score: float = 0.5, risk_level: RiskLevel = RiskLevel.MEDIUM,
                        features_json: Dict = None, model_version: str = "default",
                        explanation_text: str = None, feature_importance_json: Dict = None,
                        sandbox_results_json: Dict = None, user_feedback: int = None,
                        feedback_text: str = None, is_false_positive: bool = False):
        """Save a complete scan result to history."""
        
        # Create or get session ID (for anonymous scans)
        if not session_id:
            import uuid
            session_id = str(uuid.uuid4())[:32]
        
        # Prepare input data JSON for flexible storage
        input_data_json = None
        if any([input_url, input_email, input_text]):
            input_data_json = {
                'url': input_url,
                'email': input_email,
                'text': input_text
            }
        
        # Create scan history record
        scan_record = ScanHistory(
            user_id=user_id,
            session_id=session_id,
            scan_type=scan_type,
            input_url=input_url,
            input_email=input_email,
            input_text=input_text,
            input_data_json=input_data_json,
            risk_score=risk_score,
            risk_level=risk_level,
            features_json=json.dumps(features_json) if features_json else None,
            model_version=model_version,
            explanation_text=explanation_text,
            feature_importance_json=json.dumps(feature_importance_json) if feature_importance_json else None,
            sandbox_results_json=json.dumps(sandbox_results_json) if sandbox_results_json else None,
            user_feedback=user_feedback,
            feedback_text=feedback_text,
            is_false_positive=is_false_positive
        )
        
        self.db.add(scan_record)
        self.db.commit()
        self.db.refresh(scan_record)
        
        print(f"✓ Saved scan result: {session_id[:8]}...")
        return scan_record
    
    def get_scan_by_session(self, session_id: str) -> Optional[ScanHistory]:
        """Get scan by session ID (for browser extension callbacks)."""
        return ScanHistory.query.filter_by(session_id=session_id).first()
    
    def get_user_scans(self, user_id: int, limit: int = 50, 
                       offset: int = 0, scan_type: ScanType = None) -> List[ScanHistory]:
        """Get scans for a specific user with pagination."""
        
        query = ScanHistory.query.filter_by(user_id=user_id).order_by(
            ScanHistory.created_at.desc()
        )
        
        if scan_type:
            query = query.filter_by(scan_type=scan_type)
        
        return query.limit(limit).offset(offset).all()
    
    def get_recent_scans(self, limit: int = 100) -> List[ScanHistory]:
        """Get most recent scans (for dashboard)."""
        return ScanHistory.query.order_by(
            ScanHistory.created_at.desc()
        ).limit(limit).all()
    
    def get_scan_trends(self, user_id: int, days: int = 7) -> Dict[str, Any]:
        """Get scan trends for a user (for dashboard metrics)."""
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        scans = ScanHistory.query.filter_by(
            user_id=user_id,
            created_at=cutoff_date
        ).order_by(ScanHistory.created_at.desc()).all()
        
        # Aggregate stats
        total_scans = len(scans)
        high_risk_count = sum(1 for s in scans if s.risk_level == RiskLevel.HIGH or 
                             s.risk_level == RiskLevel.CRITICAL)
        medium_risk_count = sum(1 for s in scans if s.risk_level == RiskLevel.MEDIUM)
        
        # Calculate average risk score
        avg_risk_score = sum(s.risk_score for s in scans) / total_scans if total_scans else 0
        
        return {
            'total_scans': total_scans,
            'high_risk_count': high_risk_count,
            'medium_risk_count': medium_risk_count,
            'avg_risk_score': avg_risk_score,
            'days_analyzed': days
        }


# Global instance
_scan_history_service = None

def get_history_service(db: Session):
    """Get or create global history service instance."""
    global _scan_history_service
    if _scan_history_service is None:
        _scan_history_service = ScanHistoryService(db)
    return _scan_history_service
