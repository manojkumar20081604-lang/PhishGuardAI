"""
PhishGuard AI - Main Flask Application
Industry-Grade Cybersecurity Platform v2.0
"""

import os
import sys

# Ensure backend is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from functools import wraps
from datetime import datetime
import pickle

app = Flask(__name__, static_folder='static')
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phishguard-secret-key-2024-prod')
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# ===================== CONFIG =====================
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml_models')
os.makedirs(MODELS_DIR, exist_ok=True)

# ===================== MODELS =====================
url_model = None
text_model = None

# Initialize ML models
def init_models():
    global url_model, text_model
    
    print(f"[*] Looking for models in: {MODELS_DIR}")
    
    # Create models if not exists
    def train_if_needed():
        import subprocess
        import sys
        print("[*] Training models on first run...")
        try:
            subprocess.run([sys.executable, 'train_model.py'], capture_output=True, timeout=120)
            print("[*] Models trained!")
        except Exception as e:
            print(f"[!] Training note: {e}")
    
    # URL Model
    url_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    if os.path.exists(url_path):
        try:
            with open(url_path, 'rb') as f:
                url_model = pickle.load(f)
            print("[*] URL model loaded")
        except Exception as e:
            print(f"[!] URL model error: {e}")
            train_if_needed()
    else:
        print("[!] URL model not found - will train on use")
        train_if_needed()
    
    # Email Model
    email_path = os.path.join(MODELS_DIR, 'email_model.pkl')
    if os.path.exists(email_path):
        try:
            with open(email_path, 'rb') as f:
                text_model = pickle.load(f)
            print("[*] Email model loaded")
        except Exception as e:
            print(f"[!] Email model error: {e}")
    else:
        print("[!] Email model not found - will use heuristics")
    
    print("[*] ML Models initialized")

init_models()

# ===================== ML SERVICE =====================
def extract_url_features(url):
    """Extract 10+ features from URL"""
    import numpy as np
    import re
    
    features = []
    features.append(len(url))
    features.append(1 if url.startswith('https') else 0)
    features.append(1 if '@' in url else 0)
    features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0)
    features.append(url.count('-'))
    features.append(sum(c.isdigit() for c in url) / max(len(url), 1))
    features.append(sum(1 for c in url if c in '._~:/?#[]@!$&\'()*+,;='))
    features.append(max(0, len(urlparse(url).netloc.split('.')) - 2))
    suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq']
    features.append(1 if any(url.lower().endswith(tld) for tld in suspicious_tlds) else 0)
    features.append(len(set(url)) / max(len(url), 1))
    
    return np.array(features).reshape(1, -1)

def predict_url(url):
    """Predict URL with risk score"""
    if url_model is None:
        return heuristic_url_predict(url)
    
    try:
        features = extract_url_features(url)
        proba = url_model.predict_proba(features)[0]
        phishing_prob = proba[1]
        
        if phishing_prob >= 0.65:
            prediction = 'PHISHING'
        elif phishing_prob >= 0.35:
            prediction = 'SUSPICIOUS'
        else:
            prediction = 'SAFE'
        
        confidence = round(phishing_prob if prediction != 'SAFE' else 1-phishing_prob, 3)
        return prediction, confidence
    except Exception as e:
        print(f"[!] Prediction error: {e}")
        return heuristic_url_predict(url)

def heuristic_url_predict(url):
    """Heuristic fallback"""
    score = 0
    reasons = []
    
    if len(url) > 100:
        score += 0.2
        reasons.append("Unusually long URL")
    if '@' in url:
        score += 0.4
        reasons.append("Contains @ symbol")
    if 'login' in url.lower():
        score += 0.2
        reasons.append("Login page detected")
    import re
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 0.3
        reasons.append("IP address in URL")
    if not url.startswith('https'):
        score += 0.1
        reasons.append("No HTTPS")
    
    score = min(score, 0.95)
    if score >= 0.5:
        return 'PHISHING', round(score, 2)
    elif score >= 0.2:
        return 'SUSPICIOUS', round(score, 2)
    return 'SAFE', round(1-score, 2)

def predict_email(text):
    """Predict email/text"""
    text_lower = text.lower()
    
    # Heuristic analysis
    score = 0
    reasons = []
    
    urgency_words = ['urgent', 'immediately', '24 hours', 'suspend', 'verify', 'action required']
    for word in urgency_words:
        if word in text_lower:
            score += 0.15
            reasons.append(f"Urgency: {word}")
    
    import re
    links = len(re.findall(r'http[s]?://|www\.', text))
    if links > 3:
        score += 0.2
        reasons.append(f"Multiple suspicious links ({links})")
    
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'bank', 'netflix']
    for brand in brands:
        if brand in text_lower and ('account' in text_lower or 'verify' in text_lower):
            score += 0.2
            reasons.append(f"Brand impersonation: {brand}")
    
    score = min(score, 0.95)
    if score >= 0.5:
        return 'PHISHING', round(score, 2)
    elif score >= 0.2:
        return 'SUSPICIOUS', round(score, 2)
    return 'SAFE', round(1-score, 2)

# ===================== RISK ENGINE =====================
def calculate_risk_score(ml_prediction, ml_confidence):
    """Industry-grade risk scoring (0-100)"""
    if ml_prediction == 'PHISHING':
        base_score = int(ml_confidence * 100 + 25)
    elif ml_prediction == 'SUSPICIOUS':
        base_score = int(ml_confidence * 60 + 20)
    else:
        base_score = int((1 - ml_confidence) * 30)
    
    base_score = min(max(base_score, 0), 100)
    
    if base_score >= 61:
        level = 'PHISHING'
        color = '#ef4444'
    elif base_score >= 31:
        level = 'SUSPICIOUS'
        color = '#f59e0b'
    else:
        level = 'SAFE'
        color = '#10b981'
    
    return {
        'risk_score': base_score,
        'risk_level': level,
        'risk_color': color,
        'confidence': ml_confidence
    }

# ===================== EXPLANABLE AI =====================
def explain_prediction(url=None, text=None, prediction=None):
    """Generate explanation for prediction"""
    explanations = []
    
    if url:
        if '@' in url:
            explanations.append("URL contains @ symbol - often used to hide true destination")
        if len(url) > 100:
            explanations.append(f"URL is unusually long ({len(url)} chars)")
        if url.count('-') > 3:
            explanations.append(f"URL contains {url.count('-')} dashes - common in phishing")
        if not url.startswith('https'):
            explanations.append("URL lacks HTTPS encryption")
        suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq']
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            explanations.append("URL uses suspicious top-level domain")
    
    if text:
        text_lower = text.lower()
        if 'urgent' in text_lower or 'immediately' in text_lower:
            explanations.append("Email uses urgency tactics")
        if 'verify your account' in text_lower or 'update password' in text_lower:
            explanations.append("Email requests credential verification")
        if 'dear customer' in text_lower or 'dear user' in text_lower:
            explanations.append("Email uses generic greeting")
    
    return explanations if explanations else ["No specific suspicious patterns detected"]

# ===================== IN-MEMORY DB =====================
db = {
    "url_analysis": [],
    "email_analysis": [],
    "message_analysis": [],
    "stats": {"total_scans": 0, "phishing_detected": 0, "safe_detected": 0}
}

# ===================== RATE LIMITING =====================
from collections import defaultdict
request_times = defaultdict(list)

def rate_limit(max_requests=100, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = datetime.now()
            from datetime import timedelta
            cutoff = now - timedelta(seconds=window_seconds)
            request_times[ip] = [t for t in request_times[ip] if t > cutoff]
            if len(request_times[ip]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            request_times[ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ===================== HELPERS =====================
URGENCY_WORDS = ['urgent', 'immediately', '24 hours', 'suspend', 'verify', 'action required', 'close', 'terminate']
IMPERSONATION_WORDS = ['paypal', 'amazon', 'apple', 'microsoft', 'bank', 'irs', 'government']

def analyze_url_reasons(url, features, prediction):
    """Generate reasons for URL prediction"""
    reasons = []
    
    if features[1]: reasons.append("HTTPS present")
    else: reasons.append("No HTTPS encryption")
    
    if not features[2] and not features[3] and features[4] < 3:
        reasons.append("Clean domain structure")
    
    if features[8]: reasons.append("Suspicious TLD detected")
    if features[3]: reasons.append("Contains IP address")
    if features[2]: reasons.append("Contains @ symbol")
    if features[4] > 3: reasons.append("Unusual dash pattern")
    if features[0] > 100: reasons.append("Very long URL")
    
    if prediction == 'safe':
        reasons.append("No suspicious patterns detected")
    
    return reasons

def update_stats(prediction):
    db["stats"]["total_scans"] += 1
    if prediction in ['phishing', 'PHISHING']:
        db["stats"]["phishing_detected"] += 1
    elif prediction in ['safe', 'SAFE']:
        db["stats"]["safe_detected"] += 1

# ===================== AUTH ROUTES =====================
import hashlib

@app.route('/auth/register', methods=['POST'])
def register():
    from database import create_user
    data = request.get_json()
    
    if not data or '@' not in data.get('email', ''):
        return jsonify({'success': False, 'error': 'Valid email required'}), 400
    
    if len(data.get('password', '')) < 6:
        return jsonify({'success': False, 'error': 'Password min 6 chars'}), 400
    
    try:
        create_user(
            data['email'], 
            data.get('username', data['email'].split('@')[0]),
            data['password'],
            data.get('full_name', ''),
            data.get('institution', '')
        )
        return jsonify({'success': True, 'message': 'Registered! Please login.'})
    except Exception as e:
        if 'UNIQUE' in str(e):
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        return jsonify({'success': False, 'error': 'Registration failed'}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    from database import verify_user
    data = request.get_json()
    
    email = data.get('username', '').strip().lower()
    password = data.get('password', '').strip()
    
    user = verify_user(email, password)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 400
    
    session['user_id'] = user['id']
    session['user_email'] = user['email']
    
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'username': user['username'],
            'full_name': user.get('full_name', ''),
            'institution': user.get('institution', '')
        }
    })


@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


# ===================== API ROUTES =====================

@app.route('/api/analyze/url', methods=['POST'])
@rate_limit()
def analyze_url():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    
    url = data.get('url', '').strip()
    if not url: return jsonify({"error": "URL is required"}), 400
    if len(url) > 2048: return jsonify({"error": "URL too long"}), 400
    
    # ML Prediction
    features = extract_url_features(url)
    prediction, confidence = predict_url(url)
    
    # Calculate risk score
    risk = calculate_risk_score(prediction, confidence)
    
    # Generate explanation
    explanations = explain_prediction(url=url, prediction=prediction)
    
    # Save to memory db
    reasons = analyze_url_reasons(url, features[0].tolist() if hasattr(features[0], 'tolist') else list(features[0]), prediction)
    
    entry = {
        "id": len(db["url_analysis"]) + 1,
        "url": url[:200],
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "reasons": reasons,
        "explanations": explanations,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    db["url_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "risk_level": risk['risk_level'],
        "risk_color": risk['risk_color'],
        "confidence_percent": round(confidence * 100, 1),
        "reasons": reasons,
        "explanations": explanations,
        "features": {
            "url_length": features[0][0] if hasattr(features[0], '__iter__') else features[0][0],
            "has_https": bool(features[0][1] if hasattr(features[0], '__iter__') else features[0][0]),
            "has_at_symbol": bool(features[0][2] if hasattr(features[0], '__iter__') else 0),
            "dash_count": features[0][4] if hasattr(features[0], '__iter__') else 0
        },
        "analyzed_at": entry["analyzed_at"],
        "url": url,
        "recommendation": "DO NOT visit" if prediction == 'PHISHING' else ("Be cautious" if prediction == 'SUSPICIOUS' else "Appears safe")
    })


@app.route('/api/analyze/email', methods=['POST'])
@rate_limit()
def analyze_email():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    
    subject = data.get('subject', '')
    body = data.get('body', '').strip() or data.get('email', '').strip()
    if not body: return jsonify({"error": "Email body required"}), 400
    
    combined = (subject + " " + body).lower()
    prediction, confidence = predict_email(combined)
    risk = calculate_risk_score(prediction, confidence)
    explanations = explain_prediction(text=combined, prediction=prediction)
    
    entry = {
        "id": len(db["email_analysis"]) + 1,
        "email_subject": subject,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "reasons": explanations,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    db["email_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "risk_level": risk['risk_level'],
        "reasons": explanations,
        "analyzed_at": entry["analyzed_at"]
    })


@app.route('/api/analyze/message', methods=['POST'])
@rate_limit()
def analyze_message():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    
    message = data.get('message', '').strip()
    if not message: return jsonify({"error": "Message required"}), 400
    
    prediction, confidence = predict_email(message)
    risk = calculate_risk_score(prediction, confidence)
    explanations = explain_prediction(text=message, prediction=prediction)
    
    entry = {
        "id": len(db["message_analysis"]) + 1,
        "message_text": message[:200],
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    db["message_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk['risk_score'],
        "reasons": explanations,
        "analyzed_at": entry["analyzed_at"]
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(db["stats"])


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "models_loaded": url_model is not None,
        "version": "2.0.0"
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    """Simple chatbot without OpenAI - provides helpful security info"""
    data = request.get_json()
    message = data.get('message', '').lower()
    
    # Simple response system
    responses = {
        'phishing': "Phishing is a cybercrime where attackers trick you into revealing sensitive information by pretending to be a trustworthy entity. Always verify the sender and check URLs carefully!",
        'how to spot': "To spot phishing: 1) Check sender email address 2) Look for urgency 3) Verify links before clicking 4) Watch for spelling errors 5) Never provide passwords",
        'safe browsing': "Safe browsing tips: 1) Check HTTPS 2) Verify domain 3) Don't click suspicious links 4) Use strong passwords 5) Keep software updated",
        'password': "Strong password tips: Use 12+ characters, mix uppercase/lowercase/numbers/symbols, never reuse passwords, consider a password manager.",
        'suspicious': "If something seems suspicious, don't click! Instead, go directly to the website by typing the URL yourself.",
        'default': "I'm here to help with phishing detection! Ask me about: what is phishing, how to spot suspicious emails, safe browsing tips, or password security."
    }
    
    response = responses['default']
    for key in responses:
        if key in message:
            response = responses[key]
            break
    
    return jsonify({'success': True, 'response': response})


# ===================== STATIC FILES =====================
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/<path:filename>')
def serve_root_files(filename):
    if filename.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.json', '.woff', '.woff2', '.ttf')):
        return send_from_directory('.', filename)
    return "Not found", 404

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  PhishGuard AI v2.0 - Industry Grade")
    print("="*50)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)