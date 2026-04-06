"""
PhishGuard AI - Explainable AI Service
Shows WHY predictions are made with detailed reasoning
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class ExplainableAI:
    """
    Explainable AI - Shows why prediction was made
    
    Provides:
    - Detailed reasons for classification
    - Highlighted suspicious keywords
    - Feature importance visualization
    - Security recommendations
    """
    
    def __init__(self):
        # Define patterns with explanations
        self.url_patterns = {
            # High risk patterns
            'ip_address': {
                'pattern': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                'risk': 'HIGH',
                'explanation': 'URL uses IP address instead of domain name - common in phishing',
                'recommendation': 'Legitimate sites use domain names, not raw IP addresses'
            },
            'at_symbol': {
                'pattern': r'@',
                'risk': 'HIGH',
                'explanation': 'The @ symbol can be used to hide the real destination URL',
                'recommendation': 'Avoid clicking URLs with @ symbol - it may redirect elsewhere'
            },
            'url_length': {
                'pattern': r'.{150,}',
                'risk': 'MEDIUM',
                'explanation': 'Unusually long URL often indicates obfuscation',
                'recommendation': 'Long URLs often hide the true destination'
            },
            'double_extension': {
                'pattern': r'\.[a-z]{2,4}\.[a-z]{2,4}$',
                'risk': 'MEDIUM',
                'explanation': 'Double file extensions can hide executable files',
                'recommendation': 'Be wary of files like document.pdf.exe'
            },
            'suspicious_tld': {
                'pattern': r'\.(xyz|top|pw|tk|ml|ga|cf|gq|club|work|date)$',
                'risk': 'MEDIUM',
                'explanation': 'These top-level domains are commonly used in phishing',
                'recommendation': 'Suspicious TLDs are frequently used for phishing'
            },
            'encoded_chars': {
                'pattern': r'%[0-9a-f]{2}',
                'risk': 'LOW',
                'explanation': 'URL encoding may hide suspicious characters',
                'recommendation': 'Encoded characters can be used to bypass filters'
            },
            'subdomain_abuse': {
                'pattern': r'secure\.|login\.|account\.|verify\.',
                'risk': 'HIGH',
                'explanation': 'Suspicious keywords in subdomain can impersonate legitimate sites',
                'recommendation': 'Check the main domain, not the subdomain'
            }
        }
        
        self.email_patterns = {
            # Email patterns
            'urgency': {
                'keywords': ['urgent', 'immediately', '24 hours', '48 hours', 'action required', 'suspend', 'terminate', 'close account'],
                'risk': 'HIGH',
                'explanation': 'Urgency tactics are common in phishing to bypass critical thinking',
                'recommendation': 'Legitimate organizations rarely demand immediate action via email'
            },
            'authority': {
                'keywords': ['ceo', 'director', 'manager', 'security department', 'administrator', 'bank', 'irs', 'government'],
                'risk': 'MEDIUM',
                'explanation': 'Impersonating authorities is a common phishing tactic',
                'recommendation': 'Verify the sender through official channels'
            },
            'financial': {
                'keywords': ['bank account', 'credit card', 'social security', 'ssn', 'routing number', 'wire transfer', 'bitcoin', 'gift card'],
                'risk': 'HIGH',
                'explanation': 'Requests for financial information are almost always phishing',
                'recommendation': 'Never share financial details via email'
            },
            'credential harvesting': {
                'keywords': ['verify your account', 'update your password', 'confirm your identity', 'sign in to', 'login now', 'click here to verify'],
                'risk': 'HIGH',
                'explanation': 'Direct requests for credentials are phishing attempts',
                'recommendation': 'Navigate directly to websites, never click email links'
            },
            'generic_greeting': {
                'keywords': ['dear customer', 'dear user', 'dear member', 'valued customer', 'dear email user'],
                'risk': 'LOW',
                'explanation': 'Generic greetings often indicate mass phishing emails',
                'recommendation': 'Legitimate companies usually address you by name'
            },
            'suspicious_links': {
                'keywords': ['http://', 'click here', 'visit this link', 'open this link'],
                'risk': 'MEDIUM',
                'explanation': 'Suspicious link references in email text',
                'recommendation': 'Hover over links to see the actual URL'
            },
            'threats': {
                'keywords': ['account suspended', 'will be deleted', 'legal action', 'arrest warrant', 'prosecute', 'lawsuit'],
                'risk': 'HIGH',
                'explanation': 'Threatening language is designed to cause panic',
                'recommendation': 'Official organizations don\'t threaten via email'
            },
            'prizes': {
                'keywords': ['won', 'winner', 'prize', 'congratulations', 'you have been selected', 'claim your reward', 'free gift'],
                'risk': 'HIGH',
                'explanation': 'Too-good-to-be-true offers are usually scams',
                'recommendation': 'If you didn\'t enter, you didn\'t win'
            }
        }
    
    def explain_url(self, url: str, prediction: str, features: Dict = None) -> Dict:
        """
        Generate detailed explanation for URL prediction
        """
        explanations = []
        risk_indicators = []
        safe_indicators = []
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except:
            parsed = None
            domain = ''
        
        # Check each pattern
        for pattern_name, pattern_info in self.url_patterns.items():
            pattern = pattern_info['pattern']
            
            if pattern_name == 'url_length':
                if len(url) > 150:
                    explanations.append({
                        'pattern': pattern_name,
                        'risk': pattern_info['risk'],
                        'explanation': pattern_info['explanation'],
                        'recommendation': pattern_info['recommendation'],
                        'evidence': f'URL length: {len(url)} characters'
                    })
                    if pattern_info['risk'] == 'HIGH':
                        risk_indicators.append(f"Long URL ({len(url)} chars)")
                    else:
                        safe_indicators.append(f"URL length: {len(url)}")
            elif pattern_name == 'subdomain_abuse':
                if parsed and 'secure' in domain.replace('secure.', '') or 'login' in domain.replace('login.', ''):
                    if any(safe in domain for safe in ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com', 'paypal.com']):
                        pass  # It's a legitimate subdomain
                    else:
                        explanations.append({
                            'pattern': pattern_name,
                            'risk': pattern_info['risk'],
                            'explanation': pattern_info['explanation'],
                            'recommendation': pattern_info['recommendation'],
                            'evidence': f'Subdomain contains: {domain}'
                        })
                        risk_indicators.append('Suspicious subdomain keywords')
            elif pattern_name == 'suspicious_tld':
                suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.club', '.work', '.date']
                if any(url.lower().endswith(tld) for tld in suspicious_tlds):
                    explanations.append({
                        'pattern': pattern_name,
                        'risk': pattern_info['risk'],
                        'explanation': pattern_info['explanation'],
                        'recommendation': pattern_info['recommendation'],
                        'evidence': f'TLD: {url.split(".")[-1]}'
                    })
                    risk_indicators.append(f"Suspicious TLD: .{url.split('.')[-1]}")
            else:
                if re.search(pattern, url, re.IGNORECASE):
                    explanations.append({
                        'pattern': pattern_name,
                        'risk': pattern_info['risk'],
                        'explanation': pattern_info['explanation'],
                        'recommendation': pattern_info['recommendation'],
                        'evidence': f'Found: {re.search(pattern, url, re.IGNORECASE).group()[:50]}'
                    })
                    if pattern_info['risk'] == 'HIGH':
                        risk_indicators.append(pattern_name.replace('_', ' '))
        
        # Add safe indicators
        if url.startswith('https'):
            safe_indicators.append('HTTPS encryption present')
        if parsed and parsed.netloc:
            main_domain = parsed.netloc.split('.')[-2] if len(parsed.netloc.split('.')) > 1 else parsed.netloc
            if main_domain in ['com', 'org', 'net', 'edu', 'gov', 'co']:
                safe_indicators.append('Established TLD (.com, .org, etc.)')
        
        # Feature-based explanations if provided
        if features:
            if features.get('has_https') == False:
                risk_indicators.append('No HTTPS encryption')
            if features.get('has_ip_address'):
                risk_indicators.append('Contains IP address')
            if features.get('dash_count', 0) > 3:
                risk_indicators.append(f"Many dashes ({features.get('dash_count')})")
            if features.get('suspicious_tld'):
                risk_indicators.append('Suspicious top-level domain')
        
        return {
            'prediction': prediction,
            'explanations': explanations,
            'risk_indicators': risk_indicators,
            'safe_indicators': safe_indicators,
            'summary': self._generate_summary(prediction, explanations),
            'security_tips': self._get_security_tips(explanations)
        }
    
    def explain_email(self, text: str, prediction: str, features: Dict = None) -> Dict:
        """
        Generate detailed explanation for email/text prediction
        """
        explanations = []
        risk_indicators = []
        safe_indicators = []
        
        text_lower = text.lower()
        
        # Check each email pattern category
        for pattern_name, pattern_info in self.email_patterns.items():
            matches = []
            for keyword in pattern_info['keywords']:
                if keyword in text_lower:
                    # Find the context around the match
                    idx = text_lower.find(keyword)
                    start = max(0, idx - 30)
                    end = min(len(text), idx + len(keyword) + 30)
                    context = text[start:end]
                    matches.append(context)
            
            if matches:
                explanations.append({
                    'pattern': pattern_name,
                    'risk': pattern_info['risk'],
                    'explanation': pattern_info['explanation'],
                    'recommendation': pattern_info['recommendation'],
                    'matches': matches[:3],  # Limit to 3 examples
                    'match_count': len(matches)
                })
                
                if pattern_info['risk'] == 'HIGH':
                    risk_indicators.append(f"{pattern_name}: {len(matches)} matches")
                elif pattern_info['risk'] == 'MEDIUM':
                    safe_indicators.append(f"{pattern_name}: {len(matches)} matches")
        
        # Count links
        links = re.findall(r'http[s]?://|www\.', text)
        if len(links) > 3:
            risk_indicators.append(f"Many links ({len(links)}) detected")
        
        # Check for email-specific features
        if features:
            if features.get('urgency_phrases', 0) > 2:
                risk_indicators.append(f"High urgency ({features.get('urgency_phrases')} phrases)")
            if features.get('scam_patterns', 0) > 2:
                risk_indicators.append(f"Multiple scam patterns detected")
        
        return {
            'prediction': prediction,
            'explanations': explanations,
            'risk_indicators': risk_indicators,
            'safe_indicators': safe_indicators,
            'summary': self._generate_summary(prediction, explanations),
            'security_tips': self._get_security_tips(explanations)
        }
    
    def _generate_summary(self, prediction: str, explanations: List) -> str:
        """Generate a human-readable summary"""
        if not explanations:
            return "No specific patterns detected. URL appears clean."
        
        high_risk_count = sum(1 for e in explanations if e['risk'] == 'HIGH')
        medium_risk_count = sum(1 for e in explanations if e['risk'] == 'MEDIUM')
        
        if prediction == 'phishing':
            return f"Detected {high_risk_count} high-risk and {medium_risk_count} medium-risk suspicious patterns commonly found in phishing attempts."
        elif prediction == 'suspicious':
            return f"Found {medium_risk_count} medium-risk patterns. Exercise caution - this content has some phishing indicators."
        else:
            return "This content appears to have minimal suspicious patterns, but always stay vigilant."
    
    def _get_security_tips(self, explanations: List) -> List[str]:
        """Get security tips based on detected patterns"""
        tips = []
        
        # Collect unique tips from recommendations
        for exp in explanations:
            tip = exp.get('recommendation', '')
            if tip and tip not in tips:
                tips.append(tip)
        
        # Add general tips if list is short
        general_tips = [
            "Always verify the sender's email address",
            "Never click links in suspicious emails",
            "When in doubt, navigate directly to the website",
            "Report phishing attempts to your IT security team"
        ]
        
        tips.extend(general_tips[:4 - len(tips)])
        
        return tips[:4]
    
    def visualize_features(self, url: str = None, text: str = None) -> Dict:
        """Generate feature visualization data for UI"""
        features = []
        
        if url:
            features = [
                {'name': 'URL Length', 'value': len(url), 'normal': len(url) < 100},
                {'name': 'Has HTTPS', 'value': url.startswith('https'), 'normal': True},
                {'name': 'Has @ Symbol', 'value': '@' in url, 'normal': False},
                {'name': 'Has IP Address', 'value': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)), 'normal': False},
                {'name': 'Dash Count', 'value': url.count('-'), 'normal': url.count('-') < 3},
            ]
        
        elif text:
            word_count = len(text.split())
            features = [
                {'name': 'Word Count', 'value': word_count, 'normal': word_count < 500},
                {'name': 'Urgency Words', 'value': sum(1 for w in ['urgent', 'immediately', '24 hours'] if w in text.lower()), 'normal': False},
                {'name': 'Link Count', 'value': len(re.findall(r'http', text, re.I)), 'normal': True},
                {'name': 'Suspicious Keywords', 'value': sum(1 for w in ['verify', 'password', 'account', 'bank'] if w in text.lower()), 'normal': False},
            ]
        
        return features


# Global instance
explainer = None


def get_explainer() -> ExplainableAI:
    """Get explainable AI instance"""
    global explainer
    if explainer is None:
        explainer = ExplainableAI()
    return explainer