"""
PhishGuard AI - Threat Intelligence Service
Integrates VirusTotal, PhishTank, and Domain Reputation
"""

import requests
import socket
import whois
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
import time

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Threat Intelligence API Integration"""
    
    def __init__(self, vt_api_key: str = '', phishtank_key: str = ''):
        self.vt_api_key = vt_api_key
        self.phishtank_key = phishtank_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def check_virustotal(self, url: str) -> Dict:
        """Check URL against VirusTotal API"""
        if not self.vt_api_key:
            return {'available': False, 'reason': 'No API key configured'}
        
        # Check cache first
        cache_key = f"vt_{url}"
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if (datetime.now() - cached_time).seconds < self.cache_ttl:
                return cached_data
        
        try:
            headers = {"x-apikey": self.vt_api_key}
            
            # First get URL ID
            response = requests.post(
                f"{self.vt_base_url}/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            
            if response.status_code == 200:
                url_id = response.json()['data']['id']
                
                # Get analysis results
                analysis_response = requests.get(
                    f"{self.vt_base_url}/analyses/{url_id}",
                    headers=headers,
                    timeout=10
                )
                
                if analysis_response.status_code == 200:
                    data = analysis_response.json()['data']
                    stats = data.get('attributes', {}).get('last_analysis_stats', {})
                    
                    result = {
                        'available': True,
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'total_votes': stats.get('total', 0)
                    }
                    
                    # Cache result
                    self.cache[cache_key] = (result, datetime.now())
                    return result
            
            return {'available': False, 'error': f'API error: {response.status_code}'}
            
        except Exception as e:
            logger.error(f"[!] VirusTotal check failed: {e}")
            return {'available': False, 'error': str(e)}
    
    def check_phishtank(self, url: str) -> Dict:
        """Check URL against PhishTank API"""
        if not self.phishtank_key:
            return {'available': False, 'reason': 'No API key configured'}
        
        try:
            response = requests.post(
                'https://phishtank.com/phish_feed.php',
                data={'url': url, 'format': 'json'},
                headers={'User-Agent': 'PhishGuardAI/1.0'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'available': True,
                    'in_database': data.get('in_database', False),
                    'phish_id': data.get('phish_id'),
                    'verified': data.get('verified', 'false'),
                    'verified_at': data.get('verified_at')
                }
            
            return {'available': False, 'error': f'API error: {response.status_code}'}
            
        except Exception as e:
            logger.error(f"[!] PhishTank check failed: {e}")
            return {'available': False, 'error': str(e)}
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation using WHOIS and basic checks"""
        result = {
            'domain': domain,
            'age_days': None,
            'registration_date': None,
            'registrar': None,
            'suspicious': False,
            'risk_factors': []
        }
        
        try:
            # Get WHOIS info
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if creation_date:
                    age = (datetime.now() - creation_date).days
                    result['age_days'] = age
                    result['registration_date'] = str(creation_date)
                    
                    # New domains are suspicious (< 30 days)
                    if age < 30:
                        result['suspicious'] = True
                        result['risk_factors'].append(f"Domain is very new ({age} days)")
            
            if w.registrar:
                result['registrar'] = str(w.registrar)
            
        except Exception as e:
            logger.debug(f"WHOIS lookup failed: {e}")
        
        # Check DNS for suspicious patterns
        try:
            ip = socket.gethostbyname(domain)
            result['resolved_ip'] = ip
            
            # Check if IP is in suspicious range (basic check)
            if ip.startswith(('10.', '192.168.', '172.')):
                result['risk_factors'].append("Internal IP address")
                
        except:
            result['risk_factors'].append("Domain cannot be resolved")
        
        return result
    
    def check_url_indicators(self, url: str) -> Dict:
        """Analyze URL for suspicious indicators"""
        from urllib.parse import urlparse
        import re
        
        indicators = {
            'suspicious_patterns': [],
            'brand_mentions': [],
            'risk_score': 0
        }
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Suspicious patterns
        suspicious_patterns = [
            (r'login', 'login' in path or 'login' in query),
            (r'signin', 'signin' in path),
            (r'verify', 'verify' in path or 'verify' in query),
            (r'account', 'account' in path or 'account' in query),
            (r'secure', 'secure' in domain),
            (r'update', 'update' in path),
            (r'confirm', 'confirm' in path),
            (r'banking', 'bank' in domain or 'banking' in domain),
        ]
        
        for pattern, condition in suspicious_patterns:
            if condition:
                indicators['suspicious_patterns'].append(pattern)
                indicators['risk_score'] += 10
        
        # Brand mentions in suspicious context
        brands = ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix', 'google', 'chase', 'wellsfargo', 'bankofamerica']
        for brand in brands:
            if brand in domain and brand not in ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'netflix.com']:
                if 'login' in path or 'verify' in query or 'account' in path:
                    indicators['brand_mentions'].append(brand)
                    indicators['risk_score'] += 20
        
        # Typosquatting detection (basic)
        trusted_domains = ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com', 'netflix.com', 'paypal.com']
        for trusted in trusted_domains:
            if trusted.split('.')[0] in domain and domain != trusted:
                indicators['risk_factors'].append(f"Possible typosquatting of {trusted}")
                indicators['risk_score'] += 30
        
        # Length check
        if len(url) > 200:
            indicators['risk_factors'].append('Unusually long URL')
            indicators['risk_score'] += 10
        
        # Homograph attack detection
        if re.search(r'[а-яΑ-Я]', url):  # Cyrillic/Greek chars
            indicators['risk_factors'].append('Possible homograph attack (non-ASCII characters)')
            indicators['risk_score'] += 25
        
        return indicators
    
    def get_full_threat_report(self, url: str) -> Dict:
        """Get comprehensive threat intelligence report"""
        from urllib.parse import urlparse
        
        # Extract domain
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            domain = url
        
        report = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'virustotal': self.check_virustotal(url),
            'phishtank': self.check_phishtank(url),
            'domain_reputation': self.check_domain_reputation(domain) if domain else {},
            'url_indicators': self.check_url_indicators(url),
            'overall_risk': 0
        }
        
        # Calculate overall risk
        risk_score = 0
        
        # VirusTotal contributes up to 40 points
        if report['virustotal'].get('available'):
            vt_malicious = report['virustotal'].get('malicious', 0)
            risk_score += min(vt_malicious * 4, 40)
        
        # PhishTank contributes 30 points if found
        if report['phishtank'].get('available') and report['phishtank'].get('in_database'):
            risk_score += 30
        
        # Domain reputation contributes up to 20 points
        if report['domain_reputation'].get('suspicious'):
            risk_score += 20
        
        # URL indicators contribute up to 20 points
        risk_score += min(report['url_indicators'].get('risk_score', 0), 20)
        
        report['overall_risk'] = min(risk_score, 100)
        
        return report


# Global instance
threat_intel = None


def init_threat_intel(vt_key: str = '', phishtank_key: str = '') -> ThreatIntelligenceService:
    """Initialize threat intelligence service"""
    global threat_intel
    threat_intel = ThreatIntelligenceService(vt_key, phishtank_key)
    return threat_intel


def get_threat_intel() -> ThreatIntelligenceService:
    """Get threat intel instance"""
    global threat_intel
    if threat_intel is None:
        from config import Config
        threat_intel = ThreatIntelligenceService(Config.VIRUSTOTAL_API_KEY, Config.PHISHTANK_API_KEY)
    return threat_intel