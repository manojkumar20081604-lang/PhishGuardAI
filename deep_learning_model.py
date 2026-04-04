import numpy as np
import os
from datetime import datetime

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    from tensorflow.keras.optimizers import Adam
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

class DeepPhishingDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.input_dim = 16
        self._init_model()
    
    def _init_model(self):
        if not HAS_TENSORFLOW:
            print("[!] TensorFlow not available, using fallback")
            return
        
        model_path = os.path.join(os.path.dirname(__file__), 'models', 'deep_phishing_model.keras')
        
        if os.path.exists(model_path):
            try:
                self.model = load_model(model_path)
                self.is_trained = True
                print("[✓] Deep learning model loaded successfully")
                return
            except Exception as e:
                print(f"[!] Failed to load model: {e}")
        
        self.model = self._build_model()
        print("[✓] Deep learning model initialized")
    
    def _build_model(self):
        model = Sequential([
            Dense(128, input_dim=self.input_dim, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(32, activation='relu'),
            BatchNormalization(),
            Dropout(0.2),
            
            Dense(16, activation='relu'),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC(name='auc')]
        )
        
        return model
    
    def _create_synthetic_data(self, num_samples=2000):
        np.random.seed(42)
        
        X = []
        y = []
        
        for _ in range(num_samples // 2):
            url_length = np.random.randint(20, 50)
            has_https = 1
            has_ip = 0
            has_at = 0
            suspicious_tld = 0
            digit_count = np.random.randint(0, 10)
            encoded = 0
            subdomain = np.random.randint(0, 2)
            
            features = [
                url_length, has_https, has_ip, has_at,
                1, subdomain, digit_count, 0,
                suspicious_tld, encoded, 0, 1,
                np.random.uniform(3, 4.5), 0, np.random.randint(5, 20), np.random.randint(0, 10)
            ]
            X.append(features)
            y.append(0)
        
        for _ in range(num_samples // 2):
            url_length = np.random.randint(80, 200)
            has_https = np.random.choice([0, 1])
            has_ip = np.random.choice([0, 1])
            has_at = np.random.choice([0, 1])
            suspicious_tld = 1
            digit_count = np.random.randint(15, 50)
            encoded = np.random.randint(0, 5)
            subdomain = np.random.randint(2, 6)
            
            features = [
                url_length, has_https, has_ip, has_at,
                1, subdomain, digit_count, np.random.randint(5, 15),
                suspicious_tld, encoded, np.random.randint(0, 3), 0,
                np.random.uniform(4.5, 5.5), 1, np.random.randint(20, 100), np.random.randint(10, 50)
            ]
            X.append(features)
            y.append(1)
        
        return np.array(X), np.array(y)
    
    def train(self, X_train=None, y_train=None, epochs=50, batch_size=32):
        if not HAS_TENSORFLOW:
            print("[!] TensorFlow not available")
            return False
        
        if X_train is None or y_train is None:
            print("[*] Generating synthetic training data...")
            X_train, y_train = self._create_synthetic_data(3000)
        
        X_train = np.array(X_train).astype('float32')
        y_train = np.array(y_train).astype('float32')
        
        indices = np.random.permutation(len(X_train))
        split = int(len(X_train) * 0.8)
        
        X_tr, X_val = X_train[indices[:split]], X_train[indices[split:]]
        y_tr, y_val = y_train[indices[:split]], y_train[indices[split:]]
        
        early_stop = EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )
        
        reduce_lr = ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=0.0001
        )
        
        print("[*] Training deep learning model...")
        history = self.model.fit(
            X_tr, y_tr,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_val, y_val),
            callbacks=[early_stop, reduce_lr],
            verbose=1
        )
        
        loss, accuracy, auc = self.model.evaluate(X_val, y_val, verbose=0)
        print(f"[✓] Training complete - Accuracy: {accuracy*100:.2f}%, AUC: {auc*100:.2f}%")
        
        self._save_model()
        self.is_trained = True
        
        return {
            'accuracy': accuracy,
            'auc': auc,
            'history': history.history
        }
    
    def _save_model(self):
        model_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, 'deep_phishing_model.keras')
        self.model.save(model_path)
        print(f"[✓] Model saved to {model_path}")
    
    def predict(self, X):
        if not HAS_TENSORFLOW or self.model is None:
            return self._fallback_predict(X)
        
        X = np.array(X).reshape(1, -1).astype('float32')
        
        probability = self.model.predict(X, verbose=0)[0][0]
        
        prediction = 'Phishing' if probability > 0.5 else 'Safe'
        confidence = abs(probability - 0.5) * 200
        confidence = min(max(confidence, 50), 99.9)
        
        return {
            'prediction': prediction,
            'confidence': round(confidence, 2),
            'probability': round(float(probability) * 100, 2),
            'model': 'Deep Neural Network',
            'safe_prob': round((1 - float(probability)) * 100, 2),
            'phishing_prob': round(float(probability) * 100, 2)
        }
    
    def _fallback_predict(self, X):
        features = np.array(X).flatten()
        
        score = 0
        if len(features) >= 16:
            if features[0] > 100: score += 0.15
            if features[2] == 1: score += 0.25
            if features[3] == 1: score += 0.20
            if features[8] == 1: score += 0.15
            if features[6] > 20: score += 0.15
            if features[9] > 3: score += 0.15
        
        probability = min(score, 0.95)
        
        return {
            'prediction': 'Phishing' if probability > 0.5 else 'Safe',
            'confidence': round(min(abs(probability - 0.5) * 200, 99.9), 2),
            'probability': round(probability * 100, 2),
            'model': 'Rule-based (fallback)',
            'safe_prob': round((1 - probability) * 100, 2),
            'phishing_prob': round(probability * 100, 2)
        }
    
    def ensemble_predict(self, url_features, email_features=None, social_features=None):
        if url_features is not None:
            feature_vector = self._extract_url_features(url_features)
            return self.predict(feature_vector)
        
        return self._fallback_predict([0.5] * 16)
    
    def _extract_url_features(self, features):
        return [
            features.get('url_length', 50) / 200,
            features.get('has_https', 0.5),
            features.get('has_ip', 0),
            features.get('has_at_symbol', 0),
            features.get('has_double_slash', 0.5),
            features.get('subdomain_count', 0) / 5,
            features.get('digit_count', 0) / 50,
            features.get('special_char_count', 0) / 20,
            features.get('has_suspicious_symbols', 0),
            features.get('suspicious_tld', 0),
            features.get('encoded_chars', 0) / 10,
            features.get('www_present', 0.5),
            features.get('url_entropy', 4) / 5,
            features.get('suspicious_word_count', 0) / 5,
            features.get('path_length', 0) / 100,
            features.get('query_length', 0) / 100
        ]
    
    def get_model_info(self):
        if not HAS_TENSORFLOW or self.model is None:
            return {
                'tensorflow_available': False,
                'model_type': 'Rule-based fallback',
                'accuracy': 'N/A'
            }
        
        return {
            'tensorflow_available': True,
            'model_type': 'Deep Neural Network',
            'architecture': '4-layer DNN (128-64-32-16-1)',
            'layers': [
                'Input: 16 features',
                'Dense(128) + BatchNorm + Dropout(0.3)',
                'Dense(64) + BatchNorm + Dropout(0.3)',
                'Dense(32) + BatchNorm + Dropout(0.2)',
                'Dense(16) + Dense(1, sigmoid)'
            ],
            'optimizer': 'Adam (lr=0.001)',
            'loss': 'Binary Crossentropy',
            'is_trained': self.is_trained
        }
