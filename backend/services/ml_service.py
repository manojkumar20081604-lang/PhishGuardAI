"""
PhishGuard AI - ML Service
Multi-Model Management System
"""

import pickle
import os
import numpy as np
from typing import Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class MLService:
    """ML Model Management Service"""
    
    def __init__(self, models_dir: str):
        self.models_dir = models_dir
        self.url_model = None
        self.email_model = None
        self.url_scaler = None
        self.email_vectorizer = None
        self._load_models()
    
    def _load_models(self):
        """Load all ML models"""
        # URL Model
        url_path = os.path.join(self.models_dir, 'url_model.pkl')
        if os.path.exists(url_path):
            try:
                with open(url_path, 'rb') as f:
                    self.url_model = pickle.load(f)
                logger.info("[*] URL model loaded successfully")
            except Exception as e:
                logger.error(f"[!] Failed to load URL model: {e}")
        
        # Email Model
        email_path = os.path.join(self.models_dir, 'email_model.pkl')
        if os.path.exists(email_path):
            try:
                with open(email_path, 'rb') as f:
                    self.email_model = pickle.load(f)
                logger.info("[*] Email model loaded successfully")
            except Exception as e:
                logger.error(f"[!] Failed to load email model: {e}")
        
        # Scalers
        scaler_path = os.path.join(self.models_dir, 'scalers')
        if os.path.exists(scaler_path):
            for scaler_file in ['url_scaler.pkl', 'email_vectorizer.pkl']:
                path = os.path.join(scaler_path, scaler_file)
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            if 'url' in scaler_file:
                                self.url_scaler = pickle.load(f)
                            else:
                                self.email_vectorizer = pickle.load(f)
                    except Exception as e:
                        logger.warning(f"[!] Failed to load {scaler_file}: {e}")
    
    def extract_url_features(self, url: str) -> np.ndarray:
        """Extract 10+ features from URL for ML"""
        features = []
        
        # 1. URL length
        features.append(len(url))
        
        # 2. Has HTTPS
        features.append(1 if url.startswith('https') else 0)
        
        # 3. Has @ symbol (suspicious)
        features.append(1 if '@' in url else 0)
        
        # 4. Has IP address
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features.append(1 if re.search(ip_pattern, url) else 0)
        
        # 5. Dash count
        features.append(url.count('-'))
        
        # 6. Digit ratio
        digits = sum(c.isdigit() for c in url)
        features.append(digits / max(len(url), 1))
        
        # 7. Special char count
        special = sum(1 for c in url if c in '._~:/?#[]@!$&\'()*+,;=')
        features.append(special)
        
        # 8. Subdomain count
        parsed_url = __import__('urllib.parse', fromlist=['urlparse']).urlparse(url)
        subdomain_count = len(parsed_url.netloc.split('.')) - 2 if parsed_url.netloc else 0
        features.append(max(0, subdomain_count))
        
        # 9. Suspicious TLD
        suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.club']
        features.append(1 if any(url.lower().endswith(tld) for tld in suspicious_tlds) else 0)
        
        # 10._entropy (character diversity)
        unique_chars = len(set(url))
        features.append(unique_chars / max(len(url), 1))
        
        return np.array(features).reshape(1, -1)
    
    def predict_url(self, url: str) -> Tuple[str, float]:
        """Predict if URL is phishing"""
        if self.url_model is None:
            logger.warning("[!] URL model not loaded, using heuristic fallback")
            return self._heuristic_url_predict(url)
        
        try:
            features = self.extract_url_features(url)
            if self.url_scaler:
                features = self.url_scaler.transform(features)
            
            proba = self.url_model.predict_proba(features)[0]
            phishing_prob = proba[1]
            
            # Determine prediction
            if phishing_prob >= 0.65:
                prediction = 'phishing'
            elif phishing_prob >= 0.35:
                prediction = 'suspicious'
            else:
                prediction = 'safe'
            
            confidence = phishing_prob if prediction != 'safe' else 1 - phishing_prob
            return prediction, round(confidence, 3)
            
        except Exception as e:
            logger.error(f"[!] URL prediction error: {e}")
            return self._heuristic_url_predict(url)
    
    def _heuristic_url_predict(self, url: str) -> Tuple[str, float]:
        """Heuristic fallback for URL prediction"""
        score = 0
        reasons = []
        
        # Suspicious patterns
        if len(url) > 100:
            score += 0.2
            reasons.append("Unusually long URL")
        
        if '@' in url:
            score += 0.4
            reasons.append("Contains @ symbol (credential stuffing)")
        
        if 'login' in url.lower() or 'signin' in url.lower():
            if not any(safe in url.lower() for safe in ['google.com', 'facebook.com', 'microsoft.com']):
                score += 0.3
                reasons.append("Login page detected")
        
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
        if ip_match:
            score += 0.4
            reasons.append("IP address in URL")
        
        # HTTPS check
        if not url.startswith('https'):
            score += 0.1
            reasons.append("No HTTPS encryption")
        
        if score >= 0.5:
            return 'phishing', min(score, 0.95)
        elif score >= 0.2:
            return 'suspicious', score
        else:
            return 'safe', 1 - score
    
    def predict_email(self, text: str) -> Tuple[str, float]:
        """Predict if email/text is phishing"""
        if self.email_model is None:
            return self._heuristic_email_predict(text)
        
        try:
            text_lower = text.lower()
            
            if self.email_vectorizer:
                features = self.email_vectorizer.transform([text_lower])
            else:
                # Simple TF-IDF like features
                features = self._simple_text_features(text_lower)
            
            proba = self.email_model.predict_proba(features)[0]
            phishing_prob = proba[1]
            
            if phishing_prob >= 0.55:
                prediction = 'phishing'
            elif phishing_prob >= 0.30:
                prediction = 'suspicious'
            else:
                prediction = 'safe'
            
            confidence = phishing_prob if prediction != 'safe' else 1 - phishing_prob
            return prediction, round(confidence, 3)
            
        except Exception as e:
            logger.error(f"[!] Email prediction error: {e}")
            return self._heuristic_email_predict(text)
    
    def _simple_text_features(self, text: str) -> np.ndarray:
        """Simple text feature extraction as fallback"""
        features = []
        
        # Urgency keywords
        urgency_words = ['urgent', 'immediately', 'action required', 'suspend', 'verify', 'confirm']
        features.append(sum(1 for w in urgency_words if w in text))
        
        # Financial keywords
        financial_words = ['bank', 'account', 'password', 'credit', 'verify', 'update']
        features.append(sum(1 for w in financial_words if w in text))
        
        # Link count
        import re
        links = len(re.findall(r'http[s]?://|www\.', text))
        features.append(links)
        
        # Suspicious domains mentioned
        suspicious_domains = ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'bank']
        features.append(sum(1 for d in suspicious_domains if d in text))
        
        # Text length
        features.append(len(text) / 1000)
        
        return np.array(features).reshape(1, -1)
    
    def _heuristic_email_predict(self, text: str) -> Tuple[str, float]:
        """Heuristic fallback for email prediction"""
        text_lower = text.lower()
        score = 0
        
        # Urgency patterns
        urgency_patterns = ['urgent', 'immediately', 'action required', '24 hours', 'suspend', 'verify your account']
        for pattern in urgency_patterns:
            if pattern in text_lower:
                score += 0.15
        
        # Suspicious links
        import re
        link_count = len(re.findall(r'http[s]?://|www\.', text))
        if link_count > 3:
            score += 0.2
        
        # Impersonation attempts
        impersonation = ['amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'paypal']
        for brand in impersonation:
            if brand in text_lower and ('account' in text_lower or 'verify' in text_lower or 'password' in text_lower):
                score += 0.25
        
        # Generic greeting
        if 'dear customer' in text_lower or 'dear user' in text_lower:
            score += 0.1
        
        # Threats
        if 'suspend' in text_lower or 'close' in text_lower or 'terminate' in text_lower:
            score += 0.15
        
        score = min(score, 0.95)
        
        if score >= 0.5:
            return 'phishing', score
        elif score >= 0.2:
            return 'suspicious', score
        else:
            return 'safe', 1 - score
    
    def is_ready(self) -> bool:
        """Check if ML service is ready"""
        return self.url_model is not None or self.email_model is not None


# Global instance
ml_service = None


def init_ml_service(models_dir: str) -> MLService:
    """Initialize ML service"""
    global ml_service
    ml_service = MLService(models_dir)
    return ml_service


def get_ml_service() -> MLService:
    """Get ML service instance"""
    global ml_service
    if ml_service is None:
        from config import Config
        ml_service = MLService(Config.MODELS_DIR)
    return ml_service