"""
Threat Intelligence Cache Service - Caches results from external APIs
to avoid redundant API calls and speed up subsequent scans.
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from models import ThreatIntelCache, ScanType


class ThreatIntelCacheService:
    """Caches threat intel results from external APIs."""
    
    # Cache TTL in seconds (default 24 hours)
    DEFAULT_TTL = 86400
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_cached(self, source_type: str, identifier: str, scan_type: ScanType) -> Optional[Dict]:
        """Get cached result if exists and not expired."""
        cache_key = f"{source_type}:{identifier}"
        
        cache_record = ThreatIntelCache.query.filter_by(cache_key=cache_key).first()
        
        if cache_record:
            # Check expiration
            if cache_record.expires_at and datetime.utcnow() < cache_record.expires_at:
                print(f"✓ Cache hit for {cache_key}")
                return self._deserialize_result(source_type, cache_record)
            else:
                print(f"⚠ Cache expired for {cache_key}, refreshing...")
        
        print(f"🔄 Cache miss for {cache_key}, fetching fresh data...")
        return None
    
    def set_cache(self, source_type: str, identifier: str, scan_type: ScanType, 
                  result: Dict, ttl_hours: int = 24):
        """Store threat intel result in cache."""
        cache_key = f"{source_type}:{identifier}"
        
        # Check if we already have a record (update instead of insert)
        existing = ThreatIntelCache.query.filter_by(cache_key=cache_key).first()
        
        if existing:
            # Update existing
            existing.virustotal_data = result.get('virustotal', None)
            existing.phishtank_data = result.get('phishtank', None)
            existing.safebrowsing_data = result.get('safebrowsing', None)
            existing.urlvoid_data = result.get('urlvoid', None)
            existing.other_sources_json = json.dumps(result.get('other', {}))
            
            # Update aggregated results
            vt_result = result.get('virustotal', {})
            phish_result = result.get('phishtank', {})
            
            is_malicious = (vt_result.get('attributes', {}).get('category') == 'Malware' or
                          vt_result.get('response', {}).get('categories', []) and 
                          any(m in str(vt_result).lower() for m in ['malicious', 'phishing']))
            
            malicious_count = 0
            if is_malicious:
                malicious_count += 1
            
            existing.is_malicious = is_malicious
            existing.malicious_count = malicious_count
            existing.total_sources_checked = len([k for k in ['virustotal', 'phishtank', 
                                                               'safebrowsing', 'urlvoid'] if result.get(k)])
            
            # Set expiration (TTL)
            expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
            existing.expires_at = expires_at
            
            self.db.commit()
            print(f"✓ Updated cache for {cache_key}")
        else:
            # Create new record
            new_cache = ThreatIntelCache(
                cache_key=cache_key,
                virustotal_data=result.get('virustotal', None),
                phishtank_data=result.get('phishtank', None),
                safebrowsing_data=result.get('safebrowsing', None),
                urlvoid_data=result.get('urlvoid', None),
                other_sources_json=json.dumps(result.get('other', {})),
                is_malicious=result.get('is_malicious', False),
                malicious_count=result.get('malicious_count', 0),
                total_sources_checked=result.get('total_sources_checked', 0),
                source_type=source_type,
                expires_at=datetime.utcnow() + timedelta(hours=ttl_hours)
            )
            
            self.db.add(new_cache)
            self.db.commit()
            print(f"✓ Created new cache entry for {cache_key}")
    
    def _deserialize_result(self, source_type: str, record: ThreatIntelCache) -> Dict:
        """Convert database record to dictionary."""
        result = {}
        
        if source_type == 'virustotal':
            result['virustotal'] = record.virustotal_data
            result['phishtank'] = record.phishtank_data
            result['safebrowsing'] = record.safebrowsing_data
            result['urlvoid'] = record.urlvoid_data
            result['other'] = json.loads(record.other_sources_json) if record.other_sources_json else {}
            result['is_malicious'] = record.is_malicious
            result['malicious_count'] = record.malicious_count
            result['total_sources_checked'] = record.total_sources_checked
        
        return result
    
    def clear_cache(self, cache_key: str):
        """Clear specific cache entry."""
        cache_record = ThreatIntelCache.query.filter_by(cache_key=cache_key).first()
        if cache_record:
            self.db.delete(cache_record)
            self.db.commit()
            print(f"✓ Cleared cache for {cache_key}")


# Global instance (will be initialized with DB session later)
_cache_service = None

def get_cache_service(db: Session):
    """Get or create global cache service instance."""
    global _cache_service
    if _cache_service is None:
        _cache_service = ThreatIntelCacheService(db)
    return _cache_service
