"""
PhishGuard AI - Sandbox Simulation Module
Simulates URL behavior without actually visiting (safe analysis)
"""

import re
import socket
import requests
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse
import time

logger = logging.getLogger(__name__)


class SandboxSimulator:
    """
    Sandbox Simulation Module
    
    Safely analyzes URLs without actually visiting them:
    - URL structure analysis
    - Redirect chain prediction
    - Domain behavior simulation
    - Content type detection
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'login\.php',
            r'signin\.php',
            r'account\.php',
            r'verify\.php',
            r'secure\.php',
            r'update\.php',
            r'confirm\.php',
            r'password\.php',
            r'banking\.php',
        ]
        
        # Known legitimate domains (whitelist)
        self.whitelisted_domains = [
            'google.com', 'facebook.com', 'microsoft.com', 'amazon.com',
            'apple.com', 'twitter.com', 'linkedin.com', 'github.com',
            'paypal.com', 'netflix.com', 'instagram.com', 'youtube.com',
            'reddit.com', 'wikipedia.org', 'amazonaws.com', 'cloudflare.com'
        ]
    
    def simulate_url(self, url: str) -> Dict:
        """
        Simulate URL behavior and predict what would happen
        
        Returns:
            Dictionary with simulation results
        """
        simulation = {
            'url': url,
            'analysis_time': time.time(),
            'url_structure': {},
            'predicted_behavior': [],
            'risk_flags': [],
            'safety_assessment': 'UNKNOWN'
        }
        
        # 1. Parse URL structure
        try:
            parsed = urlparse(url)
            
            simulation['url_structure'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'is_ip': self._is_ip_address(parsed.netloc),
                'port': self._extract_port(parsed.netloc),
                'path_depth': len([p for p in parsed.path.split('/') if p])
            }
            
        except Exception as e:
            logger.error(f"[!] URL parsing error: {e}")
            simulation['error'] = str(e)
            return simulation
        
        # 2. Predict behavior based on structure
        self._analyze_path_behavior(parsed, simulation)
        
        # 3. Check domain against whitelist
        self._check_domain_whitelist(parsed.netloc, simulation)
        
        # 4. Analyze suspicious indicators
        self._analyze_suspicious_indicators(url, simulation)
        
        # 5. Determine overall safety
        simulation['safety_assessment'] = self._determine_safety(simulation)
        
        return simulation
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname)
            return True
        except:
            return False
    
    def _extract_port(self, netloc: str) -> Optional[int]:
        """Extract port from netloc"""
        if ':' in netloc:
            try:
                return int(netloc.split(':')[1])
            except:
                return None
        return None
    
    def _analyze_path_behavior(self, parsed, simulation: Dict):
        """Analyze URL path to predict behavior"""
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Check for login/credential pages
        for pattern in self.malicious_patterns:
            if re.search(pattern, path):
                simulation['predicted_behavior'].append({
                    'type': 'CREDENTIAL_PAGE',
                    'pattern': pattern,
                    'risk': 'HIGH',
                    'description': 'URL appears to be a login/credential page'
                })
                simulation['risk_flags'].append(f"Suspicious path pattern: {pattern}")
        
        # Analyze query parameters
        sensitive_params = ['email', 'username', 'password', 'token', 'code', 'pin', 'auth']
        found_sensitive = []
        
        for param in sensitive_params:
            if param in query:
                found_sensitive.append(param)
        
        if found_sensitive:
            simulation['predicted_behavior'].append({
                'type': 'SENSITIVE_DATA_COLLECTION',
                'params': found_sensitive,
                'risk': 'HIGH',
                'description': f'URL contains sensitive query parameters: {", ".join(found_sensitive)}'
            })
            simulation['risk_flags'].append(f"Collects sensitive data: {found_sensitive}")
        
        # Check for redirect parameters
        redirect_params = ['redirect', 'return', 'url', 'next', 'back', 'continue']
        for param in redirect_params:
            if param in query:
                simulation['predicted_behavior'].append({
                    'type': 'POSSIBLE_REDIRECT',
                    'param': param,
                    'risk': 'MEDIUM',
                    'description': 'URL may redirect to another site'
                })
                break
    
    def _check_domain_whitelist(self, netloc: str, simulation: Dict):
        """Check if domain is in whitelist"""
        if not netloc:
            return
            
        # Extract base domain
        parts = netloc.lower().split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            
            if base_domain in self.whitelisted_domains:
                simulation['predicted_behavior'].append({
                    'type': 'WHITELISTED_DOMAIN',
                    'domain': base_domain,
                    'risk': 'LOW',
                    'description': f'Domain is a known legitimate service ({base_domain})'
                })
            else:
                # Not in whitelist, could be suspicious
                for whitelisted in self.whitelisted_domains:
                    if whitelisted.split('.')[0] in netloc and whitelisted not in netloc:
                        simulation['risk_flags'].append(f"Possible brand impersonation: {netloc}")
                        break
    
    def _analyze_suspicious_indicators(self, url: str, simulation: Dict):
        """Analyze various suspicious indicators"""
        
        # Check for URL shortening services
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        for shortener in shorteners:
            if shortener in url.lower():
                simulation['predicted_behavior'].append({
                    'type': 'URL_SHORTENER',
                    'service': shortener,
                    'risk': 'MEDIUM',
                    'description': f'URL uses a shortener service ({shortener}) - true destination hidden'
                })
                simulation['risk_flags'].append('Uses URL shortener')
                break
        
        # Check for data URI (could contain malicious content)
        if url.lower().startswith('data:'):
            simulation['risk_flags'].append('Contains inline data - potential XSS')
            simulation['predicted_behavior'].append({
                'type': 'INLINE_DATA',
                'risk': 'HIGH',
                'description': 'URL contains inline data - potential security risk'
            })
        
        # Check for overly long URLs
        if len(url) > 200:
            simulation['risk_flags'].append('URL is unusually long - may be obfuscated')
        
        # Check for homograph attacks (non-ASCII characters)
        if re.search(r'[а-яΑ-Яέήίό]', url):
            simulation['risk_flags'].append('Contains non-ASCII characters - possible homograph attack')
    
    def _determine_safety(self, simulation: Dict) -> str:
        """Determine overall safety assessment"""
        risk_count = len(simulation.get('risk_flags', []))
        
        # Count high risk behaviors
        high_risk_count = 0
        for behavior in simulation.get('predicted_behavior', []):
            if behavior.get('risk') == 'HIGH':
                high_risk_count += 1
        
        if high_risk_count > 0:
            return 'HIGH_RISK'
        elif risk_count > 2:
            return 'SUSPICIOUS'
        elif risk_count > 0:
            return 'CAUTION'
        else:
            return 'SAFE'
    
    def get_safe_scan_summary(self, simulation: Dict) -> str:
        """Generate a human-readable summary of the simulation"""
        assessment = simulation.get('safety_assessment', 'UNKNOWN')
        behaviors = simulation.get('predicted_behavior', [])
        
        summary = f"Safety Assessment: {assessment}\n\n"
        
        if behaviors:
            summary += "Predicted Behaviors:\n"
            for b in behaviors[:5]:  # Limit to 5
                risk_emoji = '🔴' if b.get('risk') == 'HIGH' else ('🟡' if b.get('risk') == 'MEDIUM' else '🟢')
                summary += f"  {risk_emoji} {b.get('type', 'Unknown')}: {b.get('description', '')}\n"
        
        if simulation.get('risk_flags'):
            summary += f"\nRisk Flags: {', '.join(simulation['risk_flags'][:3])}"
        
        return summary


# Global instance
sandbox = None


def get_sandbox(timeout: int = 10) -> SandboxSimulator:
    """Get sandbox simulator instance"""
    global sandbox
    if sandbox is None:
        sandbox = SandboxSimulator(timeout)
    return sandbox