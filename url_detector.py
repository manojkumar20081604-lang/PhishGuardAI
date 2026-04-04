import re
from urllib.parse import urlparse
import numpy as np

class URLFeatureExtractor:
    def __init__(self):
        self.risky_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.work', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']
        self.url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'cutt.ly', 'shorturl.at']
        self.suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'password', 'signin', 'authenticate']
        self.brand_keywords = ['paypal', 'amazon', 'google', 'facebook', 'instagram', 'twitter', 'apple', 'microsoft', 'netflix', 'ebay', 'bank', 'chase', 'wellsfargo', 'citi']
    
    def extract_features(self, url):
        features = {}
        
        features['url_length'] = len(url)
        features['has_https'] = 1 if url.startswith('https://') else 0
        
        parsed = urlparse(url)
        domain = parsed.netloc
        features['domain'] = domain
        
        features['has_ip'] = 1 if self._has_ip_address(url) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_double_slash'] = 1 if '//' in url[7:] else 0
        
        features['dash_count'] = url.count('-')
        features['digit_ratio'] = self._calculate_digit_ratio(url)
        features['subdomain_depth'] = self._count_subdomains(domain)
        
        features['has_suspicious_tld'] = 1 if self._check_risky_tld(url) else 0
        features['is_shortened'] = 1 if self._is_url_shortener(url) else 0
        
        features['encoded_chars'] = url.count('%')
        features['special_chars'] = sum(1 for c in url if not c.isalnum() and c not in ['/', ':', '.', '-', '_'])
        features['www_present'] = 1 if 'www.' in url else 0
        
        features['suspicious_word_count'] = sum(1 for word in self.suspicious_keywords if word in url.lower())
        features['brand_mention_count'] = sum(1 for brand in self.brand_keywords if brand in url.lower())
        
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['has_port'] = 1 if ':' in domain and not domain.startswith('[') else 0
        
        features['entropy'] = self._calculate_entropy(url)
        
        return features
    
    def _has_ip_address(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _calculate_digit_ratio(self, url):
        digits = sum(c.isdigit() for c in url)
        return digits / max(len(url), 1)
    
    def _count_subdomains(self, domain):
        clean_domain = domain.replace('www.', '')
        parts = clean_domain.split('.')
        return max(0, len(parts) - 2)
    
    def _check_risky_tld(self, url):
        url_lower = url.lower()
        return any(url_lower.endswith(tld) for tld in self.risky_tlds)
    
    def _is_url_shortener(self, url):
        url_lower = url.lower()
        return any(shortener in url_lower for shortener in self.url_shorteners)
    
    def _calculate_entropy(self, text):
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)
    
    def analyze(self, url):
        features = self.extract_features(url)
        warnings = []
        reasons = []
        score = 0
        
        if features['url_length'] > 100:
            score += 10
            reasons.append(f"URL is unusually long ({features['url_length']} chars)")
        
        if not features['has_https'] and 'http' in url:
            score += 15
            reasons.append("No HTTPS encryption (insecure connection)")
        
        if features['has_ip']:
            score += 25
            reasons.append("Contains IP address instead of domain name")
        
        if features['has_at_symbol']:
            score += 30
            reasons.append("@ symbol detected - common phishing obfuscation")
        
        if features['has_suspicious_tld']:
            score += 15
            reasons.append("Suspicious top-level domain (.xyz, .tk, etc.)")
        
        if features['is_shortened']:
            score += 20
            reasons.append("URL shortener detected - real destination hidden")
        
        if features['digit_ratio'] > 0.3:
            score += 15
            reasons.append(f"High digit ratio ({features['digit_ratio']:.0%}) - possible obfuscation")
        
        if features['subdomain_depth'] > 3:
            score += 15
            reasons.append(f"Multiple subdomains ({features['subdomain_depth']}) - suspicious structure")
        
        if features['dash_count'] > 5:
            score += 15
            reasons.append(f"Multiple dashes ({features['dash_count']}) - mimics legitimate domain")
        
        if features['has_port']:
            score += 10
            reasons.append("Non-standard port detected")
        
        if features['encoded_chars'] > 3:
            score += 20
            reasons.append(f"URL encoding ({features['encoded_chars']} chars) - hides true destination")
        
        if features['brand_mention_count'] > 0:
            score += 10
            reasons.append(f"Contains brand name - possible impersonation")
        
        if features['suspicious_word_count'] >= 2:
            score += 15
            reasons.append(f"Multiple suspicious keywords ({features['suspicious_word_count']})")
        
        for reason in reasons:
            warnings.append(reason)
        
        threat_level = 'Low'
        if score > 50:
            threat_level = 'High'
        elif score > 25:
            threat_level = 'Medium'
        
        return {
            'score': min(score, 100),
            'threat_level': threat_level,
            'warnings': warnings,
            'reasons': reasons,
            'features': features
        }
    
    def explain_prediction(self, features, prediction):
        explanation = {
            'summary': '',
            'key_factors': [],
            'recommendation': ''
        }
        
        if prediction == 'Phishing':
            explanation['summary'] = "This URL exhibits multiple characteristics commonly found in phishing attempts."
            explanation['key_factors'] = ["URL structure is suspicious", "May impersonate a legitimate brand", "Contains obfuscation techniques"]
            explanation['recommendation'] = "Do NOT visit this URL. Verify through official channels."
        elif prediction == 'Suspicious':
            explanation['summary'] = "This URL has some concerning features but is not definitively malicious."
            explanation['key_factors'] = ["Some unusual characteristics detected", "Exercise caution if visiting"]
            explanation['recommendation'] = "Verify the URL through official sources before visiting."
        else:
            explanation['summary'] = "This URL appears to be safe based on our analysis."
            explanation['key_factors'] = ["Standard URL structure", "No obvious obfuscation detected"]
            explanation['recommendation'] = "This URL appears legitimate, but always exercise caution online."
        
        return explanation
