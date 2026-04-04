import re

class SocialMediaDetector:
    def __init__(self):
        self.fake_offer_patterns = [
            r'free\s+',
            r'win\s+',
            r'winner',
            r'congratulations',
            r'click\s+here',
            r'special\s+offer',
            r'limited\s+time',
            r'act\s+now',
            r'don\'t\s+miss',
            r'100%\s+free',
            r'no\s+cost',
            r'zero\s+cost',
            r'get\s+it\s+free',
            r'claim\s+your',
            r'gift\s+card',
            r'bitcoin',
            r'crypto'
        ]
        
        self.scam_keywords = [
            'urgent', 'immediately', 'verify', 'suspended', 'hacked',
            'compromised', 'unusual activity', 'confirm identity',
            'password', 'social security', 'bank details', 'wire transfer',
            'money gram', 'western union', 'remittance', 'inheritance',
            'million dollars', 'lottery', 'prize', 'winner', 'selected',
            'lucky', 'reward', 'points', 'bonus', 'credit'
        ]
        
        self.impersonation_indicators = [
            'official', 'verified', 'support team', 'help desk',
            'customer service', 'security team', 'administration',
            'admin', 'moderator', 'team', 'support'
        ]
        
        self.urgency_patterns = [
            r'within\s+\d+\s+hour',
            r'today\s+only',
            r'ends?\s+tonight',
            r'expires?\s+soon',
            r'limited\s+time',
            r'only\s+\d+\s+left',
            r'\d+\s+spots?\s+left',
            r'last\s+chance'
        ]
    
    def extract_features(self, text):
        features = {}
        text_lower = text.lower()
        
        features['fake_offer_count'] = sum(1 for pattern in self.fake_offer_patterns 
                                           if re.search(pattern, text_lower))
        
        features['scam_keyword_count'] = sum(1 for keyword in self.scam_keywords 
                                              if keyword in text_lower)
        
        features['impersonation_score'] = sum(1 for indicator in self.impersonation_indicators 
                                               if indicator in text_lower)
        
        features['urgency_count'] = sum(1 for pattern in self.urgency_patterns 
                                         if re.search(pattern, text_lower))
        
        features['link_count'] = len(re.findall(r'https?://[^\s]+', text_lower))
        
        features['has_emoji'] = len(re.findall(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]', text)) > 0
        
        features['has_phone'] = 1 if re.search(r'\d{3}[-.]?\d{3}[-.]?\d{4}', text) else 0
        
        features['excessive_caps'] = sum(1 for c in text if c.isupper()) / max(len(text), 1) if len(text) > 0 else 0
        
        features['word_count'] = len(text.split())
        
        features['special_chars'] = sum(1 for c in text if not c.isalnum() and not c.isspace())
        
        features['has_contact_request'] = 1 if any(phrase in text_lower for phrase in 
                                                    ['contact us', 'dm me', 'message me', 'whatsapp', 'telegram']) else 0
        
        return features
    
    def analyze(self, text):
        features = self.extract_features(text)
        warnings = []
        score = 0
        
        if features['fake_offer_count'] >= 3:
            score += 35
            warnings.append(f"Multiple fake offer indicators ({features['fake_offer_count']})")
        elif features['fake_offer_count'] >= 1:
            score += 20
            warnings.append("Contains suspicious promotional language")
        
        if features['scam_keyword_count'] >= 4:
            score += 30
            warnings.append(f"High concentration of scam keywords ({features['scam_keyword_count']})")
        elif features['scam_keyword_count'] >= 2:
            score += 15
            warnings.append("Contains multiple suspicious keywords")
        
        if features['urgency_count'] >= 2:
            score += 25
            warnings.append("Creates artificial urgency")
        
        if features['link_count'] >= 2:
            score += 20
            warnings.append(f"Multiple links in message ({features['link_count']})")
        elif features['link_count'] >= 1:
            score += 10
            warnings.append("Contains embedded link")
        
        if features['impersonation_score'] >= 2:
            score += 20
            warnings.append("Possible brand/person impersonation")
        
        if features['has_contact_request']:
            score += 15
            warnings.append("Requests private contact")
        
        if features['has_phone']:
            score += 10
            warnings.append("Contains phone number")
        
        if features['excessive_caps'] > 0.25:
            score += 15
            warnings.append("Excessive use of capital letters")
        
        if features['has_emoji']:
            score += 5
            warnings.append("Contains emojis (common in scams)")
        
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
