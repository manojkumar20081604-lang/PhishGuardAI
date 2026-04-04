import re
import os
from collections import Counter

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

class NLPProcessor:
    def __init__(self):
        self.vectorizer = None
        self.classifier = None
        self.is_trained = False
        self.urgency_patterns = [
            'urgent', 'immediately', 'right now', 'act now', 'limited time',
            'expires', 'suspended', 'verify', 'confirm', 'security alert',
            'warning', 'attention', 'final notice', 'deadline', 'within 24 hours'
        ]
        self.brand_patterns = {
            'paypal': r'paypal|pay\s*pal',
            'amazon': r'amazon|amzn',
            'bank': r'\bbank\b|hdfc|icici|sbi|chase|citi|wells\s*fargo',
            'apple': r'apple|icloud|itunes',
            'microsoft': r'microsoft|office\s*365|outlook|onedrive',
            'google': r'google|gmail|drive',
            'facebook': r'facebook|meta|instagram',
            'netflix': r'netflix',
            'ebay': r'ebay',
            'apple_pay': r'apple\s*pay|google\s*pay|amazon\s*pay'
        }
        self.scam_patterns = [
            'lottery', 'winner', 'prize', 'inheritance', 'prince',
            'million dollars', 'wire transfer', 'gift card', 'bitcoin',
            'cryptocurrency', 'password', 'ssn', 'social security',
            'bank account', 'credit card'
        ]
        self._init_models()
    
    def _init_models(self):
        if not HAS_SKLEARN:
            return
        
        model_dir = os.path.join(os.path.dirname(__file__), 'models')
        vectorizer_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
        classifier_path = os.path.join(model_dir, 'nlp_classifier.pkl')
        
        try:
            import joblib
            if os.path.exists(vectorizer_path):
                self.vectorizer = joblib.load(vectorizer_path)
            if os.path.exists(classifier_path):
                self.classifier = joblib.load(classifier_path)
                self.is_trained = True
        except:
            pass
        
        if not self.is_trained:
            self._create_fallback_data()
    
    def _create_fallback_data(self):
        safe_texts = [
            "Hi team, please find the quarterly report attached. Let me know if you have any questions.",
            "Thanks for your order! Your package will arrive in 3-5 business days.",
            "Your subscription has been renewed successfully. Receipt attached.",
            "Meeting scheduled for tomorrow at 2 PM. Calendar invite sent.",
            "Please review the document I shared and provide feedback by Friday.",
            "Great work on the presentation! The client loved it.",
            "Your password was changed successfully. If this wasn't you, contact support.",
            "Weekly newsletter: Top 5 tips for productivity this month.",
            "Invoice #12345 is ready for review. Payment due in 30 days.",
            "Reminder: Team building event this Friday at 5 PM."
        ]
        
        phishing_texts = [
            "URGENT: Your account has been suspended! Click here immediately to verify your identity and avoid permanent suspension.",
            "Congratulations! You've won $1,000,000 in our lottery! Click to claim your prize now. Limited time only!",
            "Dear customer, we detected unusual activity on your account. Verify your identity immediately by clicking the link below.",
            "Your PayPal account has been limited. Update your information now or your account will be permanently closed.",
            "SECURITY ALERT: Someone tried to access your account from another country. Verify it's you immediately.",
            "You have received a wire transfer of $50,000. Provide your bank details to receive the funds.",
            "Amazon: Your order cannot be delivered. Update your shipping address and payment method to avoid cancellation.",
            "Apple ID: Your iCloud storage is full. Your data will be deleted in 24 hours unless you verify your account.",
            "Microsoft: Your Office 365 subscription has expired. Update your billing information to continue using our services.",
            "Dear winner, you've been selected for our special promotion. Click here to claim your free gift card now!"
        ]
        
        self._train_models(safe_texts, phishing_texts)
    
    def _train_models(self, safe_texts, phishing_texts):
        if not HAS_SKLEARN:
            return
        
        try:
            all_texts = safe_texts + phishing_texts
            labels = [0] * len(safe_texts) + [1] * len(phishing_texts)
            
            self.vectorizer = TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=100,
                stop_words='english'
            )
            
            X = self.vectorizer.fit_transform(all_texts)
            self.classifier = RandomForestClassifier(n_estimators=50, random_state=42)
            self.classifier.fit(X, labels)
            self.is_trained = True
            
            self._save_models()
        except Exception as e:
            print(f"[!] NLP training failed: {e}")
    
    def _save_models(self):
        if not HAS_SKLEARN or not self.is_trained:
            return
        
        try:
            import joblib
            model_dir = os.path.join(os.path.dirname(__file__), 'models')
            os.makedirs(model_dir, exist_ok=True)
            joblib.dump(self.vectorizer, os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
            joblib.dump(self.classifier, os.path.join(model_dir, 'nlp_classifier.pkl'))
        except:
            pass
    
    def analyze_text(self, text):
        features = self.extract_features(text)
        
        nlp_prediction = {'probability': 50, 'confidence': 50}
        if self.is_trained and self.vectorizer and self.classifier:
            try:
                X = self.vectorizer.transform([text])
                prob = self.classifier.predict_proba(X)[0]
                nlp_prediction = {
                    'probability': prob[1] * 100,
                    'confidence': abs(prob[0] - prob[1]) * 100
                }
            except:
                pass
        
        combined_score = self._calculate_combined_score(features, nlp_prediction)
        
        return {
            'nlp_prediction': nlp_prediction,
            'urgency_count': features['urgency_count'],
            'brand_mentions': features['brand_mentions'],
            'scam_indicators': features['scam_count'],
            'combined_score': combined_score
        }
    
    def extract_features(self, text):
        text_lower = text.lower()
        
        urgency_count = sum(1 for pattern in self.urgency_patterns if pattern in text_lower)
        
        brand_mentions = {}
        for brand, pattern in self.brand_patterns.items():
            if re.search(pattern, text_lower):
                brand_mentions[brand] = True
        
        scam_count = sum(1 for pattern in self.scam_patterns if pattern in text_lower)
        
        return {
            'urgency_count': urgency_count,
            'brand_mentions': len(brand_mentions),
            'brand_details': list(brand_mentions.keys()),
            'scam_count': scam_count,
            'has_links': len(re.findall(r'https?://[^\s]+', text)),
            'caps_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'exclamation_count': text.count('!')
        }
    
    def _calculate_combined_score(self, features, nlp_prediction):
        score = 0
        
        score += nlp_prediction['probability'] * 0.5
        
        if features['urgency_count'] >= 3:
            score += 25
        elif features['urgency_count'] >= 1:
            score += 10
        
        if features['scam_count'] >= 2:
            score += 20
        elif features['scam_count'] >= 1:
            score += 10
        
        if features['brand_mentions'] > 0 and features['scam_count'] > 0:
            score += 15
        
        if features['has_links'] >= 2:
            score += 15
        elif features['has_links'] >= 1:
            score += 5
        
        if features['caps_ratio'] > 0.3:
            score += 10
        
        if features['exclamation_count'] > 3:
            score += 10
        
        return min(score, 100)
    
    def explain_analysis(self, text, prediction):
        features = self.extract_features(text)
        reasons = []
        
        if features['urgency_count'] > 0:
            reasons.append(f"Contains {features['urgency_count']} urgency-triggering word(s)")
        
        if features['scam_count'] > 0:
            reasons.append(f"Contains {features['scam_count']} scam-related term(s)")
        
        if features['brand_mentions'] > 0:
            reasons.append(f"Mentions {', '.join(features['brand_details'])} brand(s)")
        
        if features['has_links'] > 0:
            reasons.append(f"Contains {features['has_links']} link(s)")
        
        if features['caps_ratio'] > 0.3:
            reasons.append("Excessive use of capital letters (common in scams)")
        
        if features['exclamation_count'] > 3:
            reasons.append(f"Multiple exclamation marks ({features['exclamation_count']})")
        
        return {
            'reasons': reasons,
            'prediction': prediction,
            'urgency_level': 'High' if features['urgency_count'] >= 2 else 'Medium' if features['urgency_count'] >= 1 else 'Low'
        }
