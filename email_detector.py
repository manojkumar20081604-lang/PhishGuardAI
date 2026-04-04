import re
import numpy as np
from collections import Counter

class EmailFeatureExtractor:
    def __init__(self):
        self.urgency_words = [
            'urgent', 'immediately', 'right away', 'act now', 'limited time',
            'expire', 'suspended', 'verify', 'confirm', 'update', 'security',
            'alert', 'warning', 'danger', 'attention', 'final notice',
            'deadline', 'unauthorized', 'unusual activity', 'suspicious',
            'click here', 'call now', 'act immediately', 'within 24 hours',
            'your account', 'will be closed', 'must verify', 'confirm identity'
        ]
        
        self.suspicious_phrases = [
            'wire transfer', 'gift card', 'bitcoin', 'cryptocurrency',
            'lottery winner', 'inheritance', 'prince', 'million dollars',
            'bank account', 'social security', 'password', 'credit card',
            'ssn', 'tax refund', 'refund', 'prize', 'winner'
        ]
        
        self.threat_phrases = [
            'legal action', 'lawsuit', 'arrest', 'court', 'federal',
            'police', 'authorities', 'prosecute', 'guilty', 'deported'
        ]
    
    def extract_features(self, text):
        features = {}
        text_lower = text.lower()
        
        words = re.findall(r'\b\w+\b', text_lower)
        
        features['urgency_count'] = sum(1 for word in self.urgency_words if word in text_lower)
        features['suspicious_count'] = sum(1 for phrase in self.suspicious_phrases if phrase in text_lower)
        features['threat_count'] = sum(1 for phrase in self.threat_phrases if phrase in text_lower)
        
        features['word_count'] = len(words)
        features['sentence_count'] = len(re.split(r'[.!?]+', text))
        
        urls = re.findall(r'https?://[^\s]+', text_lower)
        features['url_count'] = len(urls)
        
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        features['email_mentions'] = len(emails)
        
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        
        features['has_attachment'] = 1 if any(word in text_lower for word in ['attachment', 'attached', 'file', 'document']) else 0
        
        features['greeting_check'] = self._check_greeting(text)
        features['signature_check'] = 1 if any(word in text_lower for word in ['regards', 'sincerely', 'best', 'thanks']) else 0
        
        features['grammar_issues'] = self._count_grammar_issues(text)
        
        features['text_entropy'] = self._calculate_entropy(text)
        
        return features
    
    def _check_greeting(self, text):
        greetings = ['dear', 'hello', 'hi', 'hey']
        text_lower = text.lower()
        for greeting in greetings:
            if greeting in text_lower[:50]:
                return 1
        return 0
    
    def _count_grammar_issues(self, text):
        issues = 0
        
        common_errors = [
            r'\b(alot)\b',
            r'\b(teh)\b',
            r'\b(recieve)\b',
            r'\b(occurence)\b',
            r'\b(seperate)\b',
            r'\b(definite)\b',
        ]
        
        for pattern in common_errors:
            if re.search(pattern, text.lower()):
                issues += 1
        
        if re.search(r'\b[A-Z]{2,}\b', text):
            issues += 1
        
        return issues
    
    def _calculate_entropy(self, text):
        if not text:
            return 0
        text = re.sub(r'[^a-zA-Z]', '', text)
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)
    
    def analyze(self, text):
        features = self.extract_features(text)
        warnings = []
        score = 0
        
        if features['urgency_count'] >= 3:
            score += 30
            warnings.append(f"High urgency language detected ({features['urgency_count']} urgency indicators)")
        elif features['urgency_count'] >= 1:
            score += 15
            warnings.append("Contains urgency-triggering words")
        
        if features['suspicious_count'] >= 2:
            score += 25
            warnings.append("Contains suspicious financial phrases")
        elif features['suspicious_count'] >= 1:
            score += 10
            warnings.append("Contains potentially suspicious content")
        
        if features['threat_count'] >= 1:
            score += 20
            warnings.append("Contains threatening language")
        
        if features['url_count'] >= 2:
            score += 20
            warnings.append(f"Multiple URLs embedded ({features['url_count']} links)")
        elif features['url_count'] >= 1:
            score += 10
            warnings.append("Contains embedded URL")
        
        if features['grammar_issues'] >= 2:
            score += 15
            warnings.append("Multiple grammar/spelling issues")
        
        if features['caps_ratio'] > 0.3:
            score += 10
            warnings.append("Excessive use of capital letters")
        
        if not features['greeting_check']:
            score += 5
            warnings.append("Missing or unusual greeting")
        
        if not features['signature_check']:
            score += 5
            warnings.append("Missing professional signature")
        
        if features['exclamation_count'] > 3:
            score += 10
            warnings.append("Excessive exclamation marks")
        
        threat_level = 'Low'
        if score > 60:
            threat_level = 'High'
        elif score > 30:
            threat_level = 'Medium'
        
        return {
            'score': min(score, 100),
            'threat_level': threat_level,
            'warnings': warnings,
            'features': features
        }
