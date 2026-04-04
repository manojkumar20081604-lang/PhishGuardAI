import re

class SMSDetector:
    def __init__(self):
        self.smishing_patterns = [
            r'bank\s+account',
            r'activate\s+now',
            r'debit\s+card',
            r'credit\s+card',
            r'pin\s+(?:is|changed)',
            r'otp\s*[:=]',
            r'verify\s+account',
            r'suspend(ed)?\s+account',
            r'urgent\s+action',
            r'kYC\s+update',
            r'compliance',
            r'reserve\s+fund',
            r'block(ed)?\s+(?:card|account)',
            r'unusual\s+(?:activity|login)',
            r'confirm\s+identity',
            r'immediate\s+attention',
            r'transaction\s+alert',
            r'refund\s+process',
            r'balance\s+update',
            r'limit\s+(?:exceeded|reached)'
        ]
        
        self.urgency_keywords = [
            'immediately', 'urgent', 'right now', 'within', 'hours', 'today',
            'expires', 'limited', 'last chance', 'act now', 'final'
        ]
        
        self.bank_keywords = [
            'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'bank', 'banking',
            'account', 'wallet', 'upi', 'neft', 'rtgs', 'debit', 'credit'
        ]
        
        self.reward_keywords = [
            'won', 'winner', 'prize', 'lottery', 'gift', 'reward', 'cashback',
            'scratch', 'reward points', 'voucher', 'coupon', 'claim'
        ]
    
    def extract_features(self, text):
        features = {}
        text_lower = text.lower()
        
        features['smishing_score'] = sum(1 for pattern in self.smishing_patterns 
                                        if re.search(pattern, text_lower))
        
        features['urgency_count'] = sum(1 for keyword in self.urgency_keywords 
                                       if keyword in text_lower)
        
        features['bank_mention'] = sum(1 for keyword in self.bank_keywords 
                                      if keyword in text_lower)
        
        features['reward_mention'] = sum(1 for keyword in self.reward_keywords 
                                        if keyword in text_lower)
        
        features['has_link'] = len(re.findall(r'https?://[^\s]+', text_lower)) + \
                              len(re.findall(r'www\.[^\s]+', text_lower)) + \
                              len(re.findall(r'bit\.ly[^\s]+', text_lower))
        
        features['has_short_code'] = 1 if re.search(r'\b\d{4,6}\b', text) else 0
        
        features['has_phone'] = len(re.findall(r'\+?\d[\d\s\-]{10,}', text))
        
        features['has_otp_request'] = 1 if re.search(r'\b(otp|password|pin)\b', text_lower) else 0
        
        features['financial_context'] = features['bank_mention'] + features['reward_mention']
        
        features['suspicious_length'] = 1 if len(text) > 300 else 0
        
        return features
    
    def analyze(self, text):
        features = self.extract_features(text)
        warnings = []
        score = 0
        
        if features['smishing_score'] >= 3:
            score += 40
            warnings.append(f"Strong SMiShing indicators detected ({features['smishing_score']})")
        elif features['smishing_score'] >= 1:
            score += 20
            warnings.append("Contains SMiShing patterns")
        
        if features['bank_mention'] >= 2:
            score += 25
            warnings.append("Multiple bank/financial mentions")
        elif features['bank_mention'] >= 1:
            score += 10
            warnings.append("Contains financial terminology")
        
        if features['urgency_count'] >= 2:
            score += 20
            warnings.append("Creates urgency to act quickly")
        
        if features['has_otp_request']:
            score += 30
            warnings.append("Requests OTP/Password - CRITICAL SCAM INDICATOR")
        
        if features['has_link'] >= 1:
            score += 20
            warnings.append(f"Contains {features['has_link']} suspicious link(s)")
        
        if features['reward_mention'] >= 1:
            score += 15
            warnings.append("Contains prize/reward language")
        
        if features['has_short_code']:
            score += 10
            warnings.append("Contains short numeric code")
        
        if features['financial_context'] >= 3:
            score += 15
            warnings.append("High financial context manipulation")
        
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
