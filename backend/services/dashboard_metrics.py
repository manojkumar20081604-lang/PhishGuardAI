"""
Dashboard Metrics Service - Aggregate and serve real-time statistics.
Provides data for admin dashboards, user analytics, and system monitoring.
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from models import (
    ScanHistory, User, RiskLevel, DashboardMetrics as MetricsModel, 
    SystemConfig, ThreatIntelCache
)


class DashboardMetricsService:
    """Manages dashboard metrics and analytics."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_overview_metrics(self, days: int = 7) -> Dict[str, Any]:
        """Get high-level overview metrics for main dashboard."""
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        scans = ScanHistory.query.filter(
            ScanHistory.created_at >= cutoff_date
        ).all()
        
        # Aggregate by risk level
        risk_distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'MINIMAL': 0
        }
        
        for scan in scans:
            if hasattr(scan.risk_level, 'name'):
                level_name = scan.risk_level.name
            else:
                level_name = str(scan.risk_level)
            
            risk_distribution[level_name] = risk_distribution.get(level_name, 0) + 1
        
        # Aggregate by scan type
        type_distribution = {}
        for scan in scans:
            if hasattr(scan.scan_type, 'name'):
                type_name = scan.scan_type.name
            else:
                type_name = str(scan.scan_type)
            
            type_distribution[type_name] = type_distribution.get(type_name, 0) + 1
        
        # Get unique users (if any)
        user_count = User.query.count() if hasattr(User, 'query') else 0
        
        return {
            'total_scans': len(scans),
            'risk_distribution': risk_distribution,
            'type_distribution': type_distribution,
            'unique_users': user_count,
            'days_analyzed': days
        }
    
    def get_user_metrics(self, user_id: int) -> Dict[str, Any]:
        """Get metrics for a specific user."""
        
        scans = ScanHistory.query.filter_by(user_id=user_id).all()
        
        if not scans:
            return {
                'total_scans': 0,
                'avg_risk_score': 0,
                'high_risk_count': 0,
                'last_scan_date': None
            }
        
        # Calculate metrics
        total_scans = len(scans)
        avg_risk_score = sum(s.risk_score for s in scans) / total_scans
        
        high_risk_count = sum(1 for s in scans if s.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        
        last_scan_date = max(s.created_at for s in scans) if scans else None
        
        return {
            'total_scans': total_scans,
            'avg_risk_score': round(avg_risk_score, 4),
            'high_risk_count': high_risk_count,
            'last_scan_date': last_scan_date.isoformat() if last_scan_date else None
        }
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics."""
        
        # Get config settings
        config = SystemConfig.query.first()
        
        # Count cache entries
        cache_count = ThreatIntelCache.query.count() if hasattr(ThreatIntelCache, 'query') else 0
        
        return {
            'config_loaded': bool(config),
            'cache_entries': cache_count,
            'uptime_hours': self._get_uptime(),
            'last_config_update': config.updated_at.isoformat() if config and config.updated_at else None
        }
    
    def _get_uptime(self) -> float:
        """Calculate approximate uptime (simplified)."""
        # In production, this would use process start time or systemd journal
        return 24.0  # Default to 24 hours for demo
    
    def get_risk_trends(self, user_id: int = None, days: int = 7) -> List[Dict]:
        """Get risk score trends over time."""
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        scans = ScanHistory.query.filter(
            ScanHistory.created_at >= cutoff_date
        ).order_by(ScanHistory.created_at.desc()).all()
        
        # Reverse to get chronological order
        scans.reverse()
        
        trends = []
        for scan in scans:
            if hasattr(scan.risk_score, 'name'):
                score = scan.risk_score.name
            else:
                score = scan.risk_score
            
            trends.append({
                'date': scan.created_at.isoformat(),
                'risk_score': round(score, 4) if isinstance(score, float) else score
            })
        
        return trends[:50]  # Limit to last 50 for performance


# Global instance
_dashboard_metrics_service = None

def get_metrics_service(db: Session):
    """Get or create global metrics service instance."""
    global _dashboard_metrics_service
    if _dashboard_metrics_service is None:
        _dashboard_metrics_service = DashboardMetricsService(db)
    return _dashboard_metrics_service
