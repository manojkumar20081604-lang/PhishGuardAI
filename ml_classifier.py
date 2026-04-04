import numpy as np
import joblib
import os

class MLClassifier:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self._init_model()
    
    def _init_model(self):
        model_path = os.path.join(os.path.dirname(__file__), 'models', 'phishing_model.pkl')
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.is_trained = True
                print("[✓] ML Model loaded successfully")
            except:
                self.model = self._create_model()
                self.is_trained = True
        else:
            self.model = self._create_model()
            self.is_trained = True
            self._save_model()
    
    def _create_model(self):
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
    
    def _save_model(self):
        model_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, 'phishing_model.pkl')
        joblib.dump(self.model, model_path)
    
    def train(self, X_train, y_train):
        if not self.is_trained:
            self._init_model()
        self.model.fit(X_train, y_train)
        self._save_model()
        print("[✓] Model trained successfully")
    
    def predict(self, X):
        if not self.is_trained:
            self._init_model()
        
        X = np.array(X).reshape(1, -1)
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        confidence = max(probability) * 100
        
        return {
            'prediction': 'Phishing' if prediction == 1 else 'Safe',
            'confidence': round(confidence, 2),
            'probabilities': {
                'safe': round(probability[0] * 100, 2),
                'phishing': round(probability[1] * 100, 2)
            }
        }
    
    def ensemble_predict(self, url_features, email_features=None, social_features=None):
        scores = []
        weights = []
        
        if url_features is not None:
            url_score = self._rule_based_score(url_features)
            scores.append(('url', url_score))
            weights.append(1.0)
        
        if email_features is not None:
            email_score = self._email_score(email_features)
            scores.append(('email', email_score))
            weights.append(1.0)
        
        if social_features is not None:
            social_score = self._social_score(social_features)
            scores.append(('social', social_score))
            weights.append(1.0)
        
        total_weight = sum(weights)
        weighted_score = sum(score * w for _, score in scores for w in zip(weights, [1/total_weight]))
        
        prediction = 'Phishing' if weighted_score > 0.5 else 'Safe'
        confidence = abs(weighted_score - 0.5) * 200
        confidence = min(max(confidence, 50), 99.9)
        
        return {
            'prediction': prediction,
            'confidence': round(confidence, 2),
            'weighted_score': round(weighted_score * 100, 2),
            'individual_scores': {name: round(score * 100, 2) for name, score in scores}
        }
    
    def _rule_based_score(self, features):
        score = 0
        
        if features.get('url_length', 0) > 100:
            score += 0.1
        if not features.get('has_https', True):
            score += 0.15
        if features.get('has_ip', False):
            score += 0.3
        if features.get('has_at_symbol', False):
            score += 0.25
        if features.get('suspicious_tld', False):
            score += 0.15
        if features.get('digit_count', 0) > 20:
            score += 0.1
        if features.get('encoded_chars', 0) > 3:
            score += 0.2
        if features.get('subdomain_count', 0) > 3:
            score += 0.1
        
        return min(score, 1.0)
    
    def _email_score(self, features):
        score = 0
        
        if features.get('urgency_count', 0) >= 3:
            score += 0.2
        elif features.get('urgency_count', 0) >= 1:
            score += 0.1
        
        if features.get('suspicious_count', 0) >= 2:
            score += 0.25
        elif features.get('suspicious_count', 0) >= 1:
            score += 0.1
        
        if features.get('threat_count', 0) >= 1:
            score += 0.2
        
        if features.get('url_count', 0) >= 2:
            score += 0.2
        elif features.get('url_count', 0) >= 1:
            score += 0.1
        
        if features.get('grammar_issues', 0) >= 2:
            score += 0.15
        
        return min(score, 1.0)
    
    def _social_score(self, features):
        score = 0
        
        if features.get('fake_offer_count', 0) >= 3:
            score += 0.35
        elif features.get('fake_offer_count', 0) >= 1:
            score += 0.2
        
        if features.get('scam_keyword_count', 0) >= 4:
            score += 0.3
        elif features.get('scam_keyword_count', 0) >= 2:
            score += 0.15
        
        if features.get('urgency_count', 0) >= 2:
            score += 0.25
        
        if features.get('link_count', 0) >= 2:
            score += 0.2
        elif features.get('link_count', 0) >= 1:
            score += 0.1
        
        if features.get('impersonation_score', 0) >= 2:
            score += 0.2
        
        return min(score, 1.0)
