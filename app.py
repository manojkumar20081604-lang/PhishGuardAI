"""
Advanced Phishing Detection & Awareness System
Flask Backend API - Production-ready
"""

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from functools import wraps
from datetime import datetime
from urllib.parse import urlparse
import json
import pickle
import os

app = Flask(__name__, static_folder='static')
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phishing-detection-secret-key-2024-change-in-prod')

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Serve root static files (style.css, main.js, etc.)
@app.route('/<path:filename>')
def serve_root_files(filename):
    if filename.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.json', '.woff', '.woff2', '.ttf')):
        return send_from_directory('.', filename)
    return "Not found", 404

app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# Rate limiting
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
                return jsonify({"error": "Rate limit exceeded. Max 100 requests/minute."}), 429
            request_times[ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize Database
import database as db_module
db_module.init_db()

# Load ML models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

print(f"[*] Looking for models in: {MODELS_DIR}")

try:
    url_model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    text_model_path = os.path.join(MODELS_DIR, 'text_model.pkl')
    
    if os.path.exists(url_model_path):
        with open(url_model_path, 'rb') as f:
            url_model = pickle.load(f)
        print("[*] URL model loaded")
    else:
        print(f"[!] URL model not found at: {url_model_path}")
        url_model = None
        
    if os.path.exists(text_model_path):
        with open(text_model_path, 'rb') as f:
            text_model = pickle.load(f)
        print("[*] Text model loaded")
    else:
        print(f"[!] Text model not found at: {text_model_path}")
        text_model = None
        
    print("[*] ML Models loaded successfully")
except Exception as e:
    print(f"[!] ML models error: {e}")
    print("[*] Run: python train_model.py to generate models")
    url_model = None
    text_model = None
    text_model = None

# In-memory database for demo/anonymous use
db = {
    "url_analysis": [],
    "email_analysis": [],
    "message_analysis": [],
    "stats": {"total_scans": 0, "phishing_detected": 0, "safe_detected": 0}
}

# Helper functions
def hash_password(password):
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def generate_token():
    import secrets
    return secrets.token_hex(32)

def get_current_user():
    user_id = session.get('user_id')
    print(f"[DEBUG] get_current_user: session user_id = {user_id}")
    if user_id:
        user = db_module.get_user_by_id(user_id)
        print(f"[DEBUG] get_current_user: found user = {user}")
        return user
    print("[DEBUG] get_current_user: no user in session")
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Please login to access this feature", "require_login": True}), 401
        return f(*args, **kwargs)
    return decorated_function

# Auth routes
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid data"}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    username = data.get('username', '').strip() or email.split('@')[0]
    full_name = data.get('full_name', '').strip()
    institution = data.get('institution', '').strip()
    
    if not email or '@' not in email:
        return jsonify({"success": False, "error": "Valid email is required"}), 400
    
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400
    
    existing = db_module.get_user_by_email(email)
    if existing:
        return jsonify({"success": False, "error": "Email already registered"}), 400
    
    db_module.create_user(email, username, password, full_name, institution)
    
    return jsonify({"success": True, "message": "Registration successful! Please login."})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid data"}), 400
    
    email = data.get('username', '').strip().lower()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"}), 400
    
    user = db_module.verify_user(email, password)
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password"}), 400
    
    session['user_id'] = user['id']
    session['user_email'] = user['email']
    
    return jsonify({
        "success": True,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "username": user['username'],
            "full_name": user['full_name'],
            "institution": user['institution'],
            "total_analyses": user['total_analyses'],
            "threats_found": user['threats_found']
        }
    })

@app.route('/auth/logout', methods=['POST'])
def logout():
    user_email = session.get('user_email')
    print(f"[DEBUG] Logging out user: {user_email}")
    session.pop('user_id', None)
    session.pop('user_email', None)
    print("[DEBUG] Session cleared")
    return jsonify({"success": True, "message": "Logged out successfully"})

@app.route('/auth/check', methods=['GET'])
def check_auth():
    user = get_current_user()
    if user:
        return jsonify({
            "logged_in": True,
            "user": {
                    "id": user['id'],
                    "email": user['email'],
                    "username": user['username'],
                    "full_name": user['full_name'],
                    "institution": user['institution'],
                    "total_analyses": user['total_analyses'],
                    "threats_found": user['threats_found']
                }
            })
    return jsonify({"logged_in": False})

@app.route('/auth/update-stats', methods=['POST'])
def update_user_stats():
    data = request.get_json()
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    if 'total_analyses' in data:
        db_module.update_user_stats(user['id'], data['total_analyses'], data.get('threats_found', 0))
    
    return jsonify({"success": True})

# User Dashboard Endpoints
@app.route('/api/user/dashboard', methods=['GET'])
@login_required
def get_user_dashboard():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    stats = db_module.get_user_stats(user['id'])
    badges = db_module.get_user_badges(user['id'])
    recent_analyses = db_module.get_user_analyses(user['id'], limit=10)
    quiz_history = db_module.get_user_quiz_history(user['id'], limit=5)
    
    return jsonify({
        "user": {
            "id": user['id'],
            "email": user['email'],
            "username": user['username'],
            "full_name": user['full_name'],
            "institution": user['institution'],
            "created_at": user['created_at']
        },
        "stats": stats,
        "badges": badges,
        "recent_analyses": recent_analyses,
        "quiz_history": quiz_history
    })

@app.route('/api/user/analyses', methods=['GET'])
@login_required
def get_user_analyses_api():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    limit = int(request.args.get('limit', 500))
    analyses = db_module.get_user_analyses(user['id'], limit)
    return jsonify(analyses)

@app.route('/api/analysis/<int:analysis_id>', methods=['GET'])
@login_required
def get_single_analysis(analysis_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    analysis = db_module.get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404
    
    if analysis.get('user_id') != user['id']:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify(analysis)

@app.route('/api/user/save-analysis', methods=['POST'])
@login_required
def save_user_analysis():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    db_module.save_analysis(
        user_id=user['id'],
        analysis_type=data.get('type', 'unknown'),
        content=data.get('content', ''),
        prediction=data.get('prediction', 'unknown'),
        confidence=data.get('confidence', 0),
        reasons=data.get('reasons', []),
        features=data.get('features', {})
    )
    
    is_threat = data.get('prediction') == 'phishing'
    db_module.update_user_stats(user['id'], 1, 1 if is_threat else 0)
    
    return jsonify({"success": True})

@app.route('/api/user/save-quiz', methods=['POST'])
@login_required
def save_user_quiz():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    db_module.save_quiz_result(
        user_id=user['id'],
        score=data.get('score', 0),
        total=data.get('total', 0),
        category=data.get('category', ''),
        difficulty=data.get('difficulty', '')
    )
    
    return jsonify({"success": True})

@app.route('/api/user/badges', methods=['GET'])
@login_required
def get_user_badges_api():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    badges = db_module.get_user_badges(user['id'])
    return jsonify(badges)

@app.route('/api/user/award-badge', methods=['POST'])
@login_required
def award_user_badge():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    badge_name = data.get('badge_name', '')
    badge_icon = data.get('badge_icon', '')
    
    db_module.award_badge(user['id'], badge_name, badge_icon)
    
    return jsonify({"success": True})

# Pre-populated demo data
db["url_analysis"] = [
    {"id": 1, "url": "http://paypa1-secure-login.com/verify@account", "prediction": "phishing",
     "confidence": 0.97, "reasons": ["No HTTPS", "@ symbol detected", "Domain impersonation", "Digit substitution (1→l)"], "analyzed_at": "2025-01-15 10:23:01"},
    {"id": 2, "url": "https://google.com", "prediction": "safe",
     "confidence": 0.99, "reasons": ["HTTPS present", "Known clean domain", "Short URL"], "analyzed_at": "2025-01-15 10:25:33"},
    {"id": 3, "url": "http://bit.ly/fake-amazon-prize", "prediction": "phishing",
     "confidence": 0.94, "reasons": ["URL shortener", "Brand impersonation", "Prize scam"], "analyzed_at": "2025-01-15 10:31:44"},
]
db["email_analysis"] = [
    {"id": 1, "email_subject": "URGENT: Verify your account NOW", "prediction": "phishing",
     "confidence": 0.96, "reasons": ["Urgency keywords", "Threat language", "Shortened URL"], "analyzed_at": "2025-01-15 11:02:15"},
    {"id": 2, "email_subject": "Your order has shipped!", "prediction": "safe",
     "confidence": 0.95, "reasons": ["Specific order details", "No urgency tactics"], "analyzed_at": "2025-01-15 11:15:02"},
]
db["message_analysis"] = [
    {"id": 1, "message_text": "🎉 CONGRATULATIONS! You won a FREE iPhone! Claim NOW: bit.ly/win", "prediction": "phishing",
     "confidence": 0.98, "reasons": ["Prize scam pattern", "Extreme urgency", "URL shortener"], "analyzed_at": "2025-01-15 12:00:11"},
]
db["stats"] = {"total_scans": 6, "phishing_detected": 4, "safe_detected": 2}

# Constants
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.link', '.work'}
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'}
URGENCY_WORDS = ['urgent', 'immediately', 'act now', 'verify now', 'limited time', 'expires',
                 'suspended', 'warning', 'final notice', 'click here', 'won', 'prize', 'free gift', 'claim']
IMPERSONATION_WORDS = ['paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'bank', 'support']
SCAM_PATTERNS = ['send to 10', 'forward to', 'earn money', 'work from home', 'get rich', 'cash prize', 'lottery', 'inheritance']

def extract_url_features(url):
    parsed = urlparse(url if '://' in url else 'http://' + url)
    url_length = len(url)
    has_https = 1 if parsed.scheme == 'https' else 0
    has_at = 1 if '@' in url else 0
    host = parsed.netloc.split(':')[0]
    has_ip = 1 if __import__('re').match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else 0
    dash_count = parsed.netloc.count('-')
    digits = sum(c.isdigit() for c in url)
    digit_ratio = digits / len(url) if url else 0
    parts = host.replace('www.', '').split('.')
    subdomain_depth = max(len(parts) - 2, 0)
    tld = '.' + parts[-1] if parts else ''
    suspicious_tld = 1 if tld.lower() in SUSPICIOUS_TLDS else 0
    has_shortener = 1 if any(s in url.lower() for s in URL_SHORTENERS) else 0
    path_depth = len([p for p in parsed.path.split('/') if p])
    return [url_length, has_https, has_at, has_ip, dash_count, digit_ratio, subdomain_depth, suspicious_tld, has_shortener, path_depth]

def analyze_url_reasons(url, features, prediction):
    reasons = []
    url_length, has_https, has_at, has_ip, dash_count, digit_ratio, subdomain_depth, suspicious_tld, has_shortener, path_depth = features
    
    if not has_https: reasons.append("No HTTPS encryption — connection is not secure")
    if has_at: reasons.append("@ symbol in URL — classic phishing trick")
    if has_ip: reasons.append("IP address used instead of domain name")
    if suspicious_tld: reasons.append("Suspicious top-level domain (TLD)")
    if dash_count >= 3: reasons.append(f"{dash_count} dashes in domain — phishing sites use many hyphens")
    if digit_ratio > 0.15: reasons.append("High digit ratio — unusual for legitimate sites")
    if subdomain_depth >= 3: reasons.append("Excessive subdomain depth — may disguise real domain")
    if has_shortener: reasons.append("URL shortener used — hides real destination")
    if url_length > 75: reasons.append(f"URL is very long ({url_length} chars)")
    
    if not reasons:
        reasons = ["HTTPS present", "Clean domain structure", "No suspicious patterns"] if prediction == 'safe' else ["Multiple suspicious characteristics"]
    return reasons

def analyze_text_reasons(text, prediction, urgency_count, link_count, impersonation_count, scam_count):
    reasons = []
    if urgency_count >= 2: reasons.append(f"{urgency_count} urgency phrases — creates false panic")
    elif urgency_count == 1: reasons.append("Urgency language detected")
    if impersonation_count > 0: reasons.append("Brand/authority name detected — possible impersonation")
    if scam_count > 0: reasons.append("Known scam patterns detected")
    if link_count > 1: reasons.append(f"{link_count} links found — excessive links is suspicious")
    caps_words = sum(1 for w in text.split() if w.isupper() and len(w) > 2)
    if caps_words >= 3: reasons.append(f"{caps_words} ALL CAPS words — manipulation tactic")
    excl_count = text.count('!')
    if excl_count >= 3: reasons.append(f"{excl_count} exclamation marks — over-excitement is red flag")
    if not reasons: reasons = ["Normal tone", "No urgency tactics", "No scam patterns"] if prediction == 'safe' else ["Text patterns match phishing templates"]
    return reasons

def update_stats(prediction):
    db["stats"]["total_scans"] += 1
    if prediction == "phishing": db["stats"]["phishing_detected"] += 1
    elif prediction == "safe": db["stats"]["safe_detected"] += 1

# Routes
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/login')
def login_page():
    user = get_current_user()
    if user:
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'login.html')

@app.route('/flex-login')
def flex_login_page():
    user = get_current_user()
    if user:
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'flex-login.html')

@app.route('/dashboard')
def dashboard_page():
    user = get_current_user()
    if user:
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'login.html')

@app.route('/api/analyze/url', methods=['POST'])
@rate_limit()
def analyze_url():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    url = data.get('url', '').strip()
    if not url: return jsonify({"error": "URL is required"}), 400
    if len(url) > 2048: return jsonify({"error": "URL too long"}), 400
    
    features = extract_url_features(url)
    
    if url_model is None:
        proba = [0.5, 0.5]
    else:
        proba = url_model.predict_proba([features])[0]
    
    phishing_prob = proba[1]
    if phishing_prob >= 0.65: prediction = "phishing"
    elif phishing_prob >= 0.35: prediction = "suspicious"
    else: prediction = "safe"
    confidence = round(phishing_prob if prediction != 'safe' else 1-phishing_prob, 3)
    reasons = analyze_url_reasons(url, features, prediction)
    
    entry = {"id": len(db["url_analysis"]) + 1, "url": url[:200], "prediction": prediction, "confidence": confidence, "reasons": reasons, "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    db["url_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True, "prediction": prediction, "confidence": confidence, "confidence_percent": round(confidence * 100, 1),
        "reasons": reasons, "features": {"url_length": features[0], "has_https": bool(features[1]),
            "has_at_symbol": bool(features[2]), "has_ip_address": bool(features[3]),
            "dash_count": features[4], "digit_ratio": round(features[5], 3), "suspicious_tld": bool(features[7])},
        "analyzed_at": entry["analyzed_at"], "url": url})

@app.route('/api/analyze/email', methods=['POST'])
@rate_limit()
def analyze_email():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    subject = data.get('subject', '')
    body = data.get('body', '').strip() or data.get('email', '').strip()
    if not body: return jsonify({"error": "Email body is required"}), 400
    if len(body) > 10000: return jsonify({"error": "Email too long"}), 400
    
    combined = (subject + " " + body).lower()
    if text_model is None:
        proba = [0.5, 0.5]
    else:
        proba = text_model.predict_proba([combined])[0]
    phishing_prob = proba[1]
    
    import re
    urgency_count = sum(1 for w in URGENCY_WORDS if w in combined)
    link_count = len(re.findall(r'https?://\S+|www\.\S+|bit\.ly\S*', body, re.I))
    impersonation_count = sum(1 for w in IMPERSONATION_WORDS if w in combined)
    rule_boost = min(0.25, urgency_count * 0.05 + impersonation_count * 0.03 + link_count * 0.04)
    if phishing_prob > 0.3: phishing_prob = min(0.99, phishing_prob + rule_boost)
    
    if phishing_prob >= 0.55: prediction = "phishing"
    elif phishing_prob >= 0.30: prediction = "suspicious"
    else: prediction = "safe"
    confidence = round(phishing_prob if prediction != 'safe' else 1-phishing_prob, 3)
    reasons = analyze_text_reasons(body, prediction, urgency_count, link_count, impersonation_count, 0)
    
    entry = {"id": len(db["email_analysis"]) + 1, "email_subject": subject[:100], "prediction": prediction, "confidence": confidence, "reasons": reasons, "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    db["email_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True, "prediction": prediction, "confidence": confidence, "confidence_percent": round(confidence * 100, 1),
        "reasons": reasons, "features": {"urgency_words_found": urgency_count, "links_detected": link_count, "brand_mentions": impersonation_count}, "analyzed_at": entry["analyzed_at"], "content": subject + " " + body[:200]})

@app.route('/api/analyze/message', methods=['POST'])
@rate_limit()
def analyze_message():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    message = data.get('message', '').strip()
    platform = data.get('platform', 'unknown')
    if not message: return jsonify({"error": "Message is required"}), 400
    if len(message) > 5000: return jsonify({"error": "Message too long"}), 400
    
    combined = message.lower()
    if text_model is None: proba = [0.5, 0.5]
    else: proba = text_model.predict_proba([combined])[0]
    phishing_prob = proba[1]
    
    import re
    urgency_count = sum(1 for w in URGENCY_WORDS if w in combined)
    link_count = len(re.findall(r'https?://\S+|www\.\S+|bit\.ly\S*', message, re.I))
    impersonation_count = sum(1 for w in IMPERSONATION_WORDS if w in combined)
    scam_count = sum(1 for p in SCAM_PATTERNS if p in combined)
    rule_boost = min(0.3, urgency_count * 0.06 + scam_count * 0.08 + link_count * 0.05)
    if phishing_prob > 0.25: phishing_prob = min(0.99, phishing_prob + rule_boost)
    
    if phishing_prob >= 0.55: prediction = "phishing"
    elif phishing_prob >= 0.30: prediction = "suspicious"
    else: prediction = "safe"
    confidence = round(phishing_prob if prediction != 'safe' else 1-phishing_prob, 3)
    reasons = analyze_text_reasons(message, prediction, urgency_count, link_count, impersonation_count, scam_count)
    
    entry = {"id": len(db["message_analysis"]) + 1, "message_text": message[:200], "platform": platform, "prediction": prediction, "confidence": confidence, "reasons": reasons, "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    db["message_analysis"].append(entry)
    update_stats(prediction)
    
    return jsonify({
        "success": True, "prediction": prediction, "confidence": confidence, "confidence_percent": round(confidence * 100, 1),
        "reasons": reasons, "features": {"urgency_phrases": urgency_count, "links_detected": link_count, "scam_patterns": scam_count}, "analyzed_at": entry["analyzed_at"], "content": message[:200]})

@app.route('/api/history', methods=['GET'])
def get_history():
    limit = min(int(request.args.get('limit', 20)), 100)
    all_entries = []
    for e in db["url_analysis"][-limit:]: all_entries.append({**e, "type": "URL", "content": e["url"][:60]})
    for e in db["email_analysis"][-limit:]: all_entries.append({**e, "type": "Email", "content": (e.get("email_subject", "") or "")[:60]})
    for e in db["message_analysis"][-limit:]: all_entries.append({**e, "type": "Message", "content": e["message_text"][:60]})
    all_entries.sort(key=lambda x: x["analyzed_at"], reverse=True)
    return jsonify(all_entries[:limit])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = db["stats"].copy()
    total = stats["total_scans"]
    stats["phishing_rate"] = round((stats["phishing_detected"] / total * 100), 1) if total > 0 else 0
    return jsonify(stats)

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    try:
        from flask import send_file
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import inch
        from datetime import datetime
        
        data = request.get_json()
        print(f"[DEBUG] PDF export request: {data}")
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        analysis_id = data.get('analysis_id')
        
        if analysis_id:
            try:
                analysis = db_module.get_analysis_by_id(analysis_id)
                print(f"[DEBUG] PDF - Retrieved analysis: {analysis}")
                if analysis:
                    data['prediction'] = analysis.get('prediction', 'Unknown')
                    data['confidence'] = analysis.get('confidence', 0)
                    # Use directly - already parsed by database function
                    data['reasons'] = analysis.get('reasons', [])
                    data['features'] = analysis.get('features', {})
                    data['type'] = analysis.get('analysis_type', 'URL')
                    data['content'] = analysis.get('content', '')
                    data['analyzed_at'] = analysis.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    print(f"[DEBUG] PDF - Updated data with prediction: {data['prediction']}")
            except Exception as e:
                print(f"[ERROR] Getting analysis: {e}")
                # Continue without analysis data
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        prediction = data.get('prediction', 'Unknown')
        confidence = data.get('confidence_percent', data.get('confidence', 0) * 100)
        reasons = data.get('reasons', [])
        features = data.get('features', {})
        analysis_type = data.get('type', 'URL')
        url_checked = data.get('url', data.get('content', ''))
        analyzed_at = data.get('analyzed_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        pred_color = '#ef4444' if prediction == 'phishing' else ('#f59e0b' if prediction == 'suspicious' else '#10b981')
        pred_label = 'DANGEROUS - PHISHING' if prediction == 'phishing' else ('WARNING - SUSPICIOUS' if prediction == 'suspicious' else 'SAFE')
        
        title_style = ParagraphStyle('Title', fontSize=28, textColor=colors.HexColor('#00d4ff'), alignment=1, spaceAfter=5, leading=32)
        elements.append(Paragraph("PHISHGUARD", title_style))
        elements.append(Paragraph("<b>AI-Powered Phishing Detection Report</b>", 
                                 ParagraphStyle('Subtitle', fontSize=11, textColor=colors.HexColor('#666666'), alignment=1)))
        elements.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor('#00d4ff'), spaceAfter=15))
        
        elements.append(Paragraph("<b>ANALYSIS DETAILS</b>", 
                                 ParagraphStyle('Section', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=8)))
        
        info_data = [
            ['Analysis Type:', str(analysis_type).upper()],
            ['Checked URL/Content:', str(url_checked)[:75] + ('...' if len(str(url_checked)) > 75 else '')],
            ['Analysis Date:', str(analyzed_at)],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        info_table = Table(info_data, colWidths=[2*inch, 4.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 20))
        
        elements.append(Paragraph("<b>RESULT</b>", 
                                 ParagraphStyle('Section', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=8)))
        
        result_data = [
            [f'{pred_label}'],
            [f'Confidence Score: {confidence:.1f}%']
        ]
        result_table = Table(result_data, colWidths=[6*inch])
        result_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(pred_color)),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, 0), 16),
            ('FONTSIZE', (0, 1), (-1, -1), 13),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
        ]))
        elements.append(result_table)
        elements.append(Spacer(1, 20))
        
        if reasons and len(reasons) > 0:
            elements.append(Paragraph("<b>THREAT ANALYSIS</b>", 
                                     ParagraphStyle('Section', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=8)))
            for i, r in enumerate(reasons, 1):
                elements.append(Paragraph(f"{i}. {r}", 
                                         ParagraphStyle('Reason', fontSize=10, textColor=colors.black, spaceBefore=4, leading=14)))
            elements.append(Spacer(1, 15))
        
        if features and len(features) > 0:
            elements.append(Paragraph("<b>FEATURES DETECTED</b>", 
                                     ParagraphStyle('Section', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=8)))
            feature_data = [[k.replace('_', ' ').title(), str(v)] for k, v in features.items()]
            feature_table = Table(feature_data, colWidths=[3*inch, 3*inch])
            feature_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
                ('BACKGROUND', (1, 0), (1, -1), colors.white),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
                ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ]))
            elements.append(feature_table)
            elements.append(Spacer(1, 20))
        
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceBefore=15, spaceAfter=15))
        elements.append(Paragraph("- Continued on next page -", 
                                 ParagraphStyle('Cont', fontSize=10, textColor=colors.gray, alignment=1, spaceAfter=10)))
        
        from reportlab.platypus import PageBreak
        elements.append(PageBreak())
        
        elements.append(Paragraph("HOW TO PROTECT YOURSELF FROM CYBER THREATS", 
                                 ParagraphStyle('Section', fontSize=14, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=10, alignment=1)))
        
        protection_tips = [
            ("<b>1. Use Strong Passwords:</b>", "Use 12+ characters with letters, numbers & symbols. Don't reuse passwords."),
            ("<b>2. Enable 2FA:</b>", "Two-Factor Authentication adds extra security. Even if password is stolen, your account stays safe."),
            ("<b>3. Check Links Before Clicking:</b>", "Look for HTTPS, avoid strange symbols. Hover to preview links."),
            ("<b>4. Be Careful with Emails:</b>", "Don't trust 'urgent' messages or 'you won prize' emails. Never share OTP or passwords."),
            ("<b>5. Keep Software Updated:</b>", "Update OS, browser, and apps regularly to fix security bugs."),
            ("<b>6. Don't Share Personal Info:</b>", "Never share passwords, bank details, or OTPs with anyone."),
            ("<b>7. Use Antivirus:</b>", "Install trusted antivirus software and scan files before opening."),
            ("<b>8. Avoid Public WiFi:</b>", "Don't login to bank accounts on public WiFi. Use VPN instead."),
            ("<b>9. Download from Trusted Sources:</b>", "Avoid cracked apps or unknown websites."),
            ("<b>10. Think Before You Click:</b>", "Most attacks succeed because of human mistakes. Stay alert!")
        ]
        
        for title, desc in protection_tips:
            elements.append(Paragraph(f"{title} {desc}", 
                                     ParagraphStyle('Tip', fontSize=9, textColor=colors.black, spaceBefore=5, leading=13)))
        
        elements.append(Spacer(1, 25))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.gray, spaceBefore=15, spaceAfter=10))
        elements.append(Paragraph("<i>Generated by PhishGuard - AI-Powered Phishing Detection System</i>", 
                                 ParagraphStyle('Footer', fontSize=8, textColor=colors.gray, alignment=1)))
        elements.append(Paragraph("<i>For educational purposes only. Always verify with official sources.</i>", 
                                 ParagraphStyle('Footer2', fontSize=8, textColor=colors.gray, alignment=1)))
        
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(buffer, mimetype='application/pdf', 
                        as_attachment=True, 
                        download_name=f'phishguard_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route('/api/export/statistics', methods=['GET'])
def export_statistics():
    try:
        from flask import send_file
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import inch
        from datetime import datetime
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('Title', fontSize=24, textColor=colors.HexColor('#00d4ff'), alignment=1)
        elements.append(Paragraph("PHISHGUARD STATISTICS", title_style))
        elements.append(Spacer(1, 20))
        
        stats = db["stats"]
        total = stats["total_scans"]
        phishing = stats["phishing_detected"]
        safe = stats["safe_detected"]
        
        stat_data = [
            ["Total Analyses", str(total)],
            ["Phishing Detected", str(phishing)],
            ["Safe Detected", str(safe)],
            ["Phishing Rate", f"{(phishing/total*100):.1f}%" if total > 0 else "0%"]
        ]
        
        table = Table(stat_data, colWidths=[2.5*inch, 2.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.gray),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<i>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
                                 ParagraphStyle('Date', fontSize=9, alignment=1, textColor=colors.gray)))
        
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(buffer, mimetype='application/pdf',
                        as_attachment=True,
                        download_name=f'phishguard_stats_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/export/history', methods=['GET'])
def export_history():
    try:
        from flask import send_file
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import inch
        from datetime import datetime
        
        user = get_current_user()
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.5*inch, leftMargin=0.5*inch, topMargin=0.5*inch, bottomMargin=0.5*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('Title', fontSize=24, textColor=colors.HexColor('#00d4ff'), alignment=1)
        elements.append(Paragraph("PHISHGUARD", title_style))
        elements.append(Paragraph("<b>Analysis History Report</b>", 
                                 ParagraphStyle('Subtitle', fontSize=12, textColor=colors.gray, alignment=1)))
        elements.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor('#00d4ff'), spaceAfter=15))
        elements.append(Spacer(1, 10))
        
        all_entries = []
        
        if user:
            user_analyses = db_module.get_user_analyses(user['id'], limit=50)
            for a in user_analyses:
                all_entries.append({
                    "type": a.get("analysis_type", "Unknown"),
                    "content": a.get("content", "")[:60],
                    "prediction": a.get("prediction", "Unknown"),
                    "confidence": a.get("confidence", 0),
                    "analyzed_at": a.get("created_at", "")
                })
        
        for e in db["url_analysis"][-20:]:
            all_entries.append({**e, "type": "URL", "content": e.get("url", e.get("url", ""))[:60]})
        for e in db["email_analysis"][-20:]:
            all_entries.append({**e, "type": "Email", "content": (e.get("email_subject", "") or "")[:60]})
        for e in db["message_analysis"][-20:]:
            all_entries.append({**e, "type": "Message", "content": e.get("message_text", "")[:60]})
        all_entries.sort(key=lambda x: x.get("analyzed_at", ""), reverse=True)
        all_entries = all_entries[:50]
        
        phishing_count = sum(1 for e in all_entries if e.get("prediction") == "phishing")
        safe_count = sum(1 for e in all_entries if e.get("prediction") == "safe")
        suspicious_count = sum(1 for e in all_entries if e.get("prediction") == "suspicious")
        
        summary_data = [
            ["Total Analyses", str(len(all_entries))],
            ["Phishing Detected", str(phishing_count)],
            ["Safe Detected", str(safe_count)],
            ["Suspicious", str(suspicious_count)]
        ]
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        if all_entries:
            elements.append(Paragraph("<b>ANALYSIS HISTORY</b>", 
                                     ParagraphStyle('Section', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=10)))
            
            header = [["Type", "Content", "Prediction", "Confidence", "Date"]]
            history_data = header + [
                [
                    e.get("type", "Unknown")[:15],
                    e.get("content", "")[:30] + "...",
                    e.get("prediction", "Unknown")[:12],
                    f"{float(e.get('confidence', 0)) * 100:.1f}%" if e.get('confidence', 0) <= 1 else f"{float(e.get('confidence', 0)):.1f}%",
                    e.get("analyzed_at", "")[:16]
                ] for e in all_entries[:30]
            ]
            
            history_table = Table(history_data, colWidths=[0.8*inch, 2.2*inch, 1*inch, 1*inch, 1.5*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('ALIGN', (2, 1), (3, -1), 'CENTER'),
            ]
            
            for i, e in enumerate(all_entries[:30], 1):
                pred = e.get("prediction", "")
                if pred == "phishing":
                    table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.red))
                elif pred == "safe":
                    table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.green))
                elif pred == "suspicious":
                    table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.orange))
            
            history_table.setStyle(TableStyle(table_style))
            elements.append(history_table)
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<i>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>", 
                                 ParagraphStyle('Date', fontSize=9, alignment=1, textColor=colors.gray)))
        
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(buffer, mimetype='application/pdf',
                        as_attachment=True,
                        download_name=f'phishguard_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# Quiz questions database
quiz_questions_db = [
    {"id": 1, "question": "What does 'HTTPS' stand for?", "option_a": "HyperText Transfer Protocol Secure", "option_b": "High Transfer Protocol System", "option_c": "HyperText Transport Process Secure", "option_d": "Hosted Transfer Protocol System", "correct_answer": "A", "explanation": "HTTPS means the connection is encrypted between your browser and the website.", "difficulty": "easy", "category": "URL"},
    {"id": 2, "question": "Which part of a URL identifies the website's main address?", "option_a": "Path", "option_b": "Domain name", "option_c": "Query string", "option_d": "Fragment", "correct_answer": "B", "explanation": "The domain name (like google.com) identifies the main website address.", "difficulty": "easy", "category": "URL"},
    {"id": 3, "question": "A URL starting with 'http://' instead of 'https://' means:", "option_a": "It is faster", "option_b": "The connection is not encrypted", "option_c": "It is more secure", "option_d": "It is a government site", "correct_answer": "B", "explanation": "HTTP lacks encryption, meaning data can be intercepted.", "difficulty": "easy", "category": "URL"},
    {"id": 4, "question": "Which of the following is a sign of a suspicious URL?", "option_a": "www.google.com", "option_b": "www.g00gle.com", "option_c": "www.github.com", "option_d": "www.amazon.com", "correct_answer": "B", "explanation": "g00gle uses zero instead of 'o' - typosquatting technique.", "difficulty": "easy", "category": "URL"},
    {"id": 5, "question": "What is URL shortening used for in phishing?", "option_a": "To make URLs faster", "option_b": "To hide the real destination of a link", "option_c": "To encrypt the website", "option_d": "To improve SEO", "correct_answer": "B", "explanation": "URL shorteners hide where a link actually leads.", "difficulty": "easy", "category": "URL"},
    {"id": 6, "question": "Before clicking a link in an email, you should:", "option_a": "Click it immediately", "option_b": "Hover over it to see the real URL", "option_c": "Reply to the email", "option_d": "Forward it to friends", "correct_answer": "B", "explanation": "Hovering reveals the actual URL destination.", "difficulty": "easy", "category": "URL"},
    {"id": 7, "question": "A padlock icon in the browser address bar means:", "option_a": "The site is 100% safe", "option_b": "The connection is encrypted", "option_c": "The site is government-owned", "option_d": "The site has no viruses", "correct_answer": "B", "explanation": "The padlock shows encryption, not that the site is trustworthy.", "difficulty": "easy", "category": "URL"},
    {"id": 8, "question": "Which of these URLs looks like a phishing attempt targeting PayPal?", "option_a": "www.paypal.com", "option_b": "www.paypal-secure-login.com", "option_c": "www.paypal.com/login", "option_d": "www.paypal.com/help", "correct_answer": "B", "explanation": "paypal-secure-login.com is NOT paypal.com - it's a different domain.", "difficulty": "easy", "category": "URL"},
    {"id": 9, "question": "What is typosquatting?", "option_a": "Hacking using typing speed", "option_b": "Registering misspelled versions of popular domains", "option_c": "Blocking websites", "option_d": "Encrypting URLs", "correct_answer": "B", "explanation": "Typosquatting uses misspellings like g00gle.com to trick users.", "difficulty": "easy", "category": "URL"},
    {"id": 10, "question": "What is phishing?", "option_a": "A type of fishing sport", "option_b": "A cyber attack to steal sensitive information via fake messages", "option_c": "A method to speed up internet", "option_d": "A type of computer virus", "correct_answer": "B", "explanation": "Phishing uses deception to steal passwords, money, or data.", "difficulty": "easy", "category": "email"},
    {"id": 11, "question": "Which of these is a common sign of a phishing email?", "option_a": "Personalized greeting with your name", "option_b": "Urgent request to click a link immediately", "option_c": "Sent from a known colleague", "option_d": "Contains your account number correctly", "correct_answer": "B", "explanation": "Urgency is a manipulation tactic used in phishing.", "difficulty": "easy", "category": "email"},
    {"id": 12, "question": "You receive an email saying 'Your account will be closed in 24 hours.' What should you do?", "option_a": "Click the link and log in", "option_b": "Contact the company directly through their official website", "option_c": "Reply with your password", "option_d": "Ignore and delete", "correct_answer": "B", "explanation": "Always verify through official channels, never click email links.", "difficulty": "easy", "category": "email"},
    {"id": 13, "question": "A legitimate bank will NEVER ask you to:", "option_a": "Send you a receipt", "option_b": "Provide your PIN via email", "option_c": "Update your address online", "option_d": "Send you a new card", "correct_answer": "B", "explanation": "Banks never request PINs or passwords via email.", "difficulty": "easy", "category": "email"},
    {"id": 14, "question": "What is 'spam' email?", "option_a": "Emails from your boss", "option_b": "Unsolicited bulk email often containing ads or scams", "option_c": "Encrypted email", "option_d": "Email with attachments", "correct_answer": "B", "explanation": "Spam is unwanted bulk messaging, often malicious.", "difficulty": "easy", "category": "email"},
    {"id": 15, "question": "Which email sender looks suspicious?", "option_a": "support@amazon.com", "option_b": "support@amaz0n-help.ru", "option_c": "noreply@google.com", "option_d": "info@paypal.com", "correct_answer": "B", "explanation": "amaz0n-help.ru uses zero and .ru domain - clear signs of phishing.", "difficulty": "easy", "category": "email"},
    {"id": 16, "question": "An email claiming you won a lottery you never entered is most likely:", "option_a": "Real - claim your prize!", "option_b": "A phishing or scam attempt", "option_c": "A government notification", "option_d": "A tax refund", "correct_answer": "B", "explanation": "You can't win a lottery you never entered.", "difficulty": "easy", "category": "email"},
    {"id": 17, "question": "What should you do if you receive a suspicious email attachment?", "option_a": "Open it to check", "option_b": "Do not open it; scan with antivirus or delete", "option_c": "Forward it to friends", "option_d": "Print it out", "correct_answer": "B", "explanation": "Never open suspicious attachments - they may contain malware.", "difficulty": "easy", "category": "email"},
    {"id": 18, "question": "Poor grammar and spelling in an email is often a sign of:", "option_a": "A casual sender", "option_b": "A phishing attempt", "option_c": "A high-priority message", "option_d": "An automated system", "correct_answer": "B", "explanation": "Professional companies proofread their communications.", "difficulty": "easy", "category": "email"},
    {"id": 19, "question": "What is the safest action when an email asks for your password?", "option_a": "Provide it if the email looks official", "option_b": "Never provide your password via email", "option_c": "Provide it only if asked twice", "option_d": "Send a hint instead", "correct_answer": "B", "explanation": "Legitimate services never ask for passwords via email.", "difficulty": "easy", "category": "email"},
    {"id": 20, "question": "What is 'smishing'?", "option_a": "A cooking technique", "option_b": "Phishing attacks carried out via SMS text messages", "option_c": "A software bug", "option_d": "A type of firewall", "correct_answer": "B", "explanation": "Smishing = SMS + Phishing = text message scams.", "difficulty": "easy", "category": "sms"},
    {"id": 21, "question": "You receive an SMS: 'Your package is held. Click here: bit.ly/xj8k2'. You should:", "option_a": "Click immediately to get your package", "option_b": "Verify through the official courier website", "option_c": "Reply with your address", "option_d": "Call the number in the SMS", "correct_answer": "B", "explanation": "Never click SMS links - verify directly on courier website.", "difficulty": "easy", "category": "sms"},
    {"id": 22, "question": "A text message claiming to be from your bank asks for your OTP. This is:", "option_a": "Normal bank procedure", "option_b": "A smishing attack", "option_c": "A security check", "option_d": "An account upgrade", "correct_answer": "B", "explanation": "Banks never ask for OTPs via SMS.", "difficulty": "easy", "category": "sms"},
    {"id": 23, "question": "Which is a red flag in an SMS message?", "option_a": "Message from a saved contact", "option_b": "Urgency + suspicious link + unknown sender", "option_c": "Delivery confirmation from Amazon", "option_d": "Bank balance alert", "correct_answer": "B", "explanation": "Urgency + unknown sender + link = scam.", "difficulty": "easy", "category": "sms"},
    {"id": 24, "question": "OTP stands for:", "option_a": "One Time Password", "option_b": "Online Transfer Protocol", "option_c": "Open Text Pass", "option_d": "Operator Transfer PIN", "correct_answer": "A", "explanation": "OTP = One Time Password, a single-use code.", "difficulty": "easy", "category": "sms"},
    {"id": 25, "question": "Should you ever share an OTP received on your phone with anyone?", "option_a": "Yes, if they claim to be from your bank", "option_b": "No, never share OTPs with anyone", "option_c": "Yes, if it's an emergency", "option_d": "Only with family members", "correct_answer": "B", "explanation": "Never share OTPs - they're meant only for you.", "difficulty": "easy", "category": "sms"},
    {"id": 26, "question": "What is social engineering in cybersecurity?", "option_a": "Building social media apps", "option_b": "Manipulating people psychologically to reveal confidential information", "option_c": "Engineering social networks", "option_d": "Hacking using social media APIs", "correct_answer": "B", "explanation": "Social engineering exploits human psychology, not technical flaws.", "difficulty": "easy", "category": "social"},
    {"id": 27, "question": "What is 'vishing'?", "option_a": "Visual phishing via images", "option_b": "Voice phishing - scams conducted over phone calls", "option_c": "Phishing via video calls", "option_d": "A type of malware", "correct_answer": "B", "explanation": "Vishing = Voice + Phishing = phone call scams.", "difficulty": "easy", "category": "social"},
    {"id": 28, "question": "You should use a strong, unique password for each online account because:", "option_a": "It's a government rule", "option_b": "If one account is hacked, others remain safe", "option_c": "Websites require it", "option_d": "It looks more professional", "correct_answer": "B", "explanation": "One compromised password won't affect other accounts.", "difficulty": "easy", "category": "social"},
    {"id": 29, "question": "Two-Factor Authentication (2FA) adds security by:", "option_a": "Requiring two passwords", "option_b": "Requiring a second verification step beyond your password", "option_c": "Encrypting your account twice", "option_d": "Blocking all logins from new devices", "correct_answer": "B", "explanation": "2FA requires something you know + something you have.", "difficulty": "easy", "category": "social"},
    {"id": 30, "question": "Which of these is a strong password?", "option_a": "password123", "option_b": "yourname1999", "option_c": "Tr!9@kL#2mZ", "option_d": "123456789", "correct_answer": "C", "explanation": "Strong passwords mix uppercase, lowercase, numbers, and symbols.", "difficulty": "easy", "category": "social"},
    {"id": 31, "question": "What does 'malware' mean?", "option_a": "Male software", "option_b": "Malicious software designed to harm systems", "option_c": "Mail software", "option_d": "Management software", "correct_answer": "B", "explanation": "Malware = Malicious Software = software designed to harm.", "difficulty": "easy", "category": "general"},
    {"id": 32, "question": "A firewall is used to:", "option_a": "Speed up your internet", "option_b": "Block unauthorized access to a network", "option_c": "Store passwords", "option_d": "Encrypt emails", "correct_answer": "B", "explanation": "Firewalls filter network traffic to block threats.", "difficulty": "easy", "category": "general"},
    {"id": 33, "question": "What is ransomware?", "option_a": "Software that speeds up your PC", "option_b": "Malware that encrypts your files and demands payment", "option_c": "Antivirus software", "option_d": "A type of browser", "correct_answer": "B", "explanation": "Ransomware locks your files until you pay (usually don't pay).", "difficulty": "easy", "category": "general"},
    {"id": 34, "question": "Antivirus software should be:", "option_a": "Installed once and never updated", "option_b": "Kept updated regularly", "option_c": "Only used on Windows", "option_d": "Only needed for emails", "correct_answer": "B", "explanation": "Regular updates protect against new threats.", "difficulty": "easy", "category": "general"},
    {"id": 35, "question": "What is the safest way to connect to the internet in a public place?", "option_a": "Use any free Wi-Fi available", "option_b": "Use a VPN with a trusted network", "option_c": "Share someone else's hotspot", "option_d": "Turn off all security settings", "correct_answer": "B", "explanation": "VPN encrypts your traffic on public networks.", "difficulty": "easy", "category": "general"},
    {"id": 36, "question": "VPN stands for:", "option_a": "Virtual Private Network", "option_b": "Verified Public Node", "option_c": "Virtual Protocol Network", "option_d": "Visible Privacy Network", "correct_answer": "A", "explanation": "VPN creates an encrypted private connection over public networks.", "difficulty": "easy", "category": "general"},
    {"id": 37, "question": "What should you do to protect your accounts?", "option_a": "Use the same password everywhere", "option_b": "Keep software updated, use strong passwords, enable 2FA", "option_c": "Only use public computers", "option_d": "Share passwords with friends", "correct_answer": "B", "explanation": "Multiple security practices together are most effective.", "difficulty": "easy", "category": "general"},
    {"id": 38, "question": "What is a data breach?", "option_a": "When a dam breaks", "option_b": "Unauthorized access to and theft of confidential data", "option_c": "A software update", "option_d": "A firewall failure", "correct_answer": "B", "explanation": "Data breach = unauthorized access to private information.", "difficulty": "easy", "category": "general"},
    {"id": 39, "question": "Which of the following is NOT a cybersecurity best practice?", "option_a": "Using strong passwords", "option_b": "Sharing your password with close friends", "option_c": "Enabling 2FA", "option_d": "Keeping software updated", "correct_answer": "B", "explanation": "Never share passwords, even with friends.", "difficulty": "easy", "category": "general"},
    {"id": 40, "question": "What is the purpose of a CAPTCHA?", "option_a": "To slow down your internet", "option_b": "To verify you are a human and not a bot", "option_c": "To encrypt your data", "option_d": "To block cookies", "correct_answer": "B", "explanation": "CAPTCHAs distinguish humans from automated bots.", "difficulty": "easy", "category": "general"},
    # MEDIUM QUESTIONS
    {"id": 41, "question": "Which URL checking tool can reveal whether a shortened URL is safe?", "option_a": "Google Translate", "option_b": "VirusTotal or CheckShortURL", "option_c": "Notepad", "option_d": "Windows Defender only", "correct_answer": "B", "explanation": "Tools like VirusTotal scan URLs against known threat databases.", "difficulty": "medium", "category": "URL"},
    {"id": 42, "question": "What is homograph attack in phishing URLs?", "option_a": "Sending identical emails repeatedly", "option_b": "Using lookalike Unicode characters in domain names to impersonate legitimate sites", "option_c": "Copying an entire website", "option_d": "Redirecting via HTTP", "correct_answer": "B", "explanation": "Homograph attacks use similar-looking characters from different alphabets.", "difficulty": "medium", "category": "URL"},
    {"id": 43, "question": "Which URL is most suspicious? A) https://secure.bank.com/login B) https://bank.com.secure-verify.net/login", "option_a": "A - it uses HTTPS", "option_b": "B - the real domain is secure-verify.net, not bank.com", "option_c": "Both are equally safe", "option_d": "Neither is suspicious", "correct_answer": "B", "explanation": "In B, bank.com appears in subdomain but real domain is secure-verify.net.", "difficulty": "medium", "category": "URL"},
    {"id": 44, "question": "A website uses HTTPS. Does this guarantee it is not a phishing site?", "option_a": "Yes - HTTPS means fully safe", "option_b": "No - attackers can also get SSL certificates for phishing sites", "option_c": "Only if it has a padlock", "option_d": "Yes - all HTTPS sites are verified", "correct_answer": "B", "explanation": "HTTPS only encrypts the connection, doesn't verify the site is legitimate.", "difficulty": "medium", "category": "URL"},
    {"id": 45, "question": "What is spear phishing?", "option_a": "Mass phishing emails sent to thousands", "option_b": "Targeted phishing aimed at a specific individual using personalized information", "option_c": "Phishing via USB drives", "option_d": "Phishing via phone calls", "correct_answer": "B", "explanation": "Spear phishing targets specific people with customized attacks.", "difficulty": "medium", "category": "email"},
    {"id": 46, "question": "What is whaling in cybersecurity?", "option_a": "Phishing targeting marine companies", "option_b": "Highly targeted phishing attacks aimed at executives or high-profile individuals", "option_c": "Phishing using whale-themed content", "option_d": "Blocking large emails", "correct_answer": "B", "explanation": "Whaling targets big targets like CEOs and executives.", "difficulty": "medium", "category": "email"},
    {"id": 47, "question": "SPF (Sender Policy Framework) helps with:", "option_a": "Encrypting email content", "option_b": "Verifying that email comes from an authorized mail server for that domain", "option_c": "Blocking spam keywords", "option_d": "Compressing email size", "correct_answer": "B", "explanation": "SPF prevents email spoofing by verifying sending servers.", "difficulty": "medium", "category": "email"},
    {"id": 48, "question": "What does DKIM stand for in email security?", "option_a": "Dynamic Key Internet Mail", "option_b": "DomainKeys Identified Mail - a method to validate email authenticity", "option_c": "Direct Key Infrastructure Management", "option_d": "Domain Key Internet Mode", "correct_answer": "B", "explanation": "DKIM adds a digital signature to emails to verify sender identity.", "difficulty": "medium", "category": "email"},
    {"id": 49, "question": "DMARC policy in email does what?", "option_a": "Blocks all emails with links", "option_b": "Tells receiving servers how to handle emails that fail SPF/DKIM checks", "option_c": "Encrypts email attachments", "option_d": "Speeds up email delivery", "correct_answer": "B", "explanation": "DMARC tells recipients what to do with suspicious emails.", "difficulty": "medium", "category": "email"},
    {"id": 50, "question": "What is SIM swapping?", "option_a": "Exchanging SIMs with a friend", "option_b": "Fraudulently transferring a victim's phone number to an attacker's SIM to intercept OTPs", "option_c": "Upgrading your SIM card", "option_d": "Using dual-SIM phones", "correct_answer": "B", "explanation": "SIM swap fraud lets attackers receive your SMS OTPs.", "difficulty": "medium", "category": "sms"},
    {"id": 51, "question": "How do attackers use smishing to bypass 2FA?", "option_a": "They guess the OTP", "option_b": "They trick victims into sharing OTPs via fake urgent SMS messages", "option_c": "They hack into the server", "option_d": "They block the OTP SMS", "correct_answer": "B", "explanation": "Social engineering bypasses technical controls.", "difficulty": "medium", "category": "sms"},
    {"id": 52, "question": "What is the best technical defense against SIM swap attacks?", "option_a": "Using a prepaid SIM", "option_b": "Using app-based authenticators instead of SMS-based 2FA", "option_c": "Changing your number frequently", "option_d": "Blocking all SMS", "correct_answer": "B", "explanation": "App-based 2FA (like Google Authenticator) can't be SIM-swapped.", "difficulty": "medium", "category": "sms"},
    {"id": 53, "question": "What is 'quid pro quo' in social engineering?", "option_a": "A Latin legal term", "option_b": "Offering a service or benefit in exchange for information or access", "option_c": "A type of DDoS attack", "option_d": "A password reset technique", "correct_answer": "B", "explanation": "Quid pro quo = 'you give me X, I give you Y' manipulation.", "difficulty": "medium", "category": "social"},
    {"id": 54, "question": "What is 'dumpster diving' in cybersecurity?", "option_a": "Hacking servers in dumpsters", "option_b": "Searching through discarded materials (papers, drives) for sensitive information", "option_c": "A type of SQL attack", "option_d": "Deleting system logs", "correct_answer": "B", "explanation": "Physical security includes destroying sensitive documents.", "difficulty": "medium", "category": "social"},
    {"id": 55, "question": "Which best describes a 'man-in-the-middle' (MITM) attack?", "option_a": "One person managing two conversations", "option_b": "An attacker secretly intercepts and possibly alters communication between two parties", "option_c": "A network crash caused by overloading", "option_d": "A firewall misconfiguration", "correct_answer": "B", "explanation": "MITM attacks eavesdrop by positioning between two communicating parties.", "difficulty": "medium", "category": "social"},
    {"id": 56, "question": "What is 'credential stuffing'?", "option_a": "Storing credentials in a USB", "option_b": "Using leaked username/password pairs from one breach to try logging into other services", "option_c": "Creating strong passwords", "option_d": "Encrypting login credentials", "correct_answer": "B", "explanation": "Credential stuffing exploits password reuse across sites.", "difficulty": "medium", "category": "general"},
    {"id": 57, "question": "What is a botnet?", "option_a": "A network of robots", "option_b": "A network of infected computers controlled by an attacker to conduct coordinated attacks", "option_c": "A type of antivirus", "option_d": "A secure server network", "correct_answer": "B", "explanation": "Botnets are networks of compromised devices used for attacks.", "difficulty": "medium", "category": "general"},
    {"id": 58, "question": "What is 'pharming'?", "option_a": "Running a farm website", "option_b": "Redirecting users to fraudulent websites without their knowledge, even when they type the correct URL", "option_c": "Phishing via pharmacy websites", "option_d": "Sending emails about farming", "correct_answer": "B", "explanation": "Pharming poisons DNS to redirect users to fake sites.", "difficulty": "medium", "category": "general"},
    {"id": 59, "question": "What is 'session hijacking'?", "option_a": "Attending unauthorized sessions", "option_b": "Stealing an authenticated session token to gain unauthorized access to a user's account", "option_c": "Crashing a web session", "option_d": "Blocking user sessions", "correct_answer": "B", "explanation": "Session hijacking steals your logged-in session cookie.", "difficulty": "medium", "category": "general"},
    {"id": 60, "question": "What is 'zero-day exploit'?", "option_a": "A bug found on Day 0 of product launch only", "option_b": "A vulnerability that is exploited before the vendor has released a patch", "option_c": "A virus that activates at midnight", "option_d": "A firewall with no rules", "correct_answer": "B", "explanation": "Zero-day = vulnerability known to attackers before developers know about it.", "difficulty": "medium", "category": "general"},
    {"id": 61, "question": "What should you do immediately after realizing you've given your bank credentials to a phishing site?", "option_a": "Wait to see if anything happens", "option_b": "Call your bank immediately, change credentials, and monitor for fraudulent transactions", "option_c": "Delete your email account", "option_d": "Restart your computer", "correct_answer": "B", "explanation": "Quick action can limit damage - report and secure immediately.", "difficulty": "medium", "category": "general"},
    {"id": 62, "question": "What is 'punycode' and how is it used in phishing?", "option_a": "A fun coding language for beginners", "option_b": "Encoding for internationalized domain names - attackers use it to create lookalike URLs using non-ASCII characters", "option_c": "A URL compression algorithm", "option_d": "A type of DNS record", "correct_answer": "B", "explanation": "Punycode can make paypal.com look identical to paypal.com.", "difficulty": "medium", "category": "URL"},
    {"id": 63, "question": "What is 'angler phishing'?", "option_a": "Phishing using fishing metaphors", "option_b": "Attackers impersonating customer support on social media to steal credentials from users seeking help", "option_c": "Phishing targeting anglers", "option_d": "Phishing via email attachments only", "correct_answer": "B", "explanation": "Angler phishing targets people seeking help on social media.", "difficulty": "medium", "category": "social"},
    {"id": 64, "question": "What is a 'drive-by download' associated with malicious URLs?", "option_a": "Downloading files while driving", "option_b": "Malware automatically downloaded when visiting a compromised URL without user interaction", "option_c": "Downloading a browser extension", "option_d": "A fast download from CDN", "correct_answer": "B", "explanation": "Drive-by downloads infect you just by visiting a malicious page.", "difficulty": "medium", "category": "URL"},
    {"id": 65, "question": "What is 'BEC' (Business Email Compromise)?", "option_a": "A business email client", "option_b": "A scam where attackers impersonate executives to trick employees into wire transfers or data sharing", "option_c": "Bulk email campaign", "option_d": "A type of email encryption", "correct_answer": "B", "explanation": "BEC costs organizations billions by impersonating executives.", "difficulty": "medium", "category": "email"},
    {"id": 66, "question": "What is 'threat intelligence' in cybersecurity?", "option_a": "Making threats to hackers", "option_b": "Information about current and emerging threats used to prepare and defend against cyber attacks", "option_c": "A hacker's skill level", "option_d": "A government surveillance program", "correct_answer": "B", "explanation": "Threat intelligence helps organizations stay ahead of attackers.", "difficulty": "medium", "category": "general"},
    {"id": 67, "question": "What is 'sandboxing' in malware analysis?", "option_a": "Playing in a sandbox", "option_b": "Running suspicious files in an isolated environment to observe behavior without risking the real system", "option_c": "Building firewall rules", "option_d": "Encrypting files before opening", "correct_answer": "B", "explanation": "Sandboxing safely analyzes malware in isolation.", "difficulty": "medium", "category": "general"},
    {"id": 68, "question": "What does 'Indicators of Compromise' (IoC) mean?", "option_a": "Signs that your antivirus is working", "option_b": "Observable artifacts (malicious IPs, domains, email headers, file hashes) that indicate a system has been compromised", "option_c": "A legal compliance indicator", "option_d": "A network performance metric", "correct_answer": "B", "explanation": "IoCs help identify and respond to breaches.", "difficulty": "medium", "category": "general"},
    {"id": 69, "question": "What is 'MFA fatigue attack' (prompt bombing)?", "option_a": "When MFA apps run out of battery", "option_b": "Sending repeated MFA push notifications to overwhelm and frustrate the victim until they accidentally approve", "option_c": "A brute force attack on MFA servers", "option_d": "A technical exploit of the MFA protocol", "correct_answer": "B", "explanation": "MFA fatigue exploits human frustration to get approvals.", "difficulty": "medium", "category": "general"},
    {"id": 70, "question": "What is 'QR code phishing' (Quishing)?", "option_a": "Phishing via QR code reader apps", "option_b": "Embedding phishing URLs in QR codes within emails - traditional email security scans text URLs but often cannot decode QR codes", "option_c": "A physical QR code placed on objects", "option_d": "Hacking via QR code scanners", "correct_answer": "B", "explanation": "Quishing bypasses email filters by hiding URLs in QR codes.", "difficulty": "medium", "category": "email"},
    # HARD QUESTIONS
    {"id": 71, "question": "In ML-based phishing URL detection, which feature is most reliable?", "option_a": "URL length alone", "option_b": "Lexical features combined with WHOIS age, DNS records, and page content analysis", "option_c": "Presence of HTTPS", "option_d": "Number of slashes in URL", "correct_answer": "B", "explanation": "ML models combine multiple features for better accuracy.", "difficulty": "hard", "category": "URL"},
    {"id": 72, "question": "How does 'fast flux' DNS technique help attackers evade phishing takedowns?", "option_a": "Encrypting DNS responses", "option_b": "Rapidly rotating IP addresses associated with a domain to keep the phishing site alive despite takedowns", "option_c": "Using multiple domain extensions", "option_d": "Blocking DNS queries from security researchers", "correct_answer": "B", "explanation": "Fast flux makes it harder to blacklist malicious domains.", "difficulty": "hard", "category": "URL"},
    {"id": 73, "question": "What is 'domain generation algorithm' (DGA) in malware?", "option_a": "An SEO tool for generating domain ideas", "option_b": "Malware that automatically generates many domain names to use as C2 servers, making blacklisting ineffective", "option_c": "A WHOIS privacy service", "option_d": "A DNS caching method", "correct_answer": "B", "explanation": "DGA creates constantly changing domains to evade detection.", "difficulty": "hard", "category": "URL"},
    {"id": 74, "question": "What is 'IDN homograph attack' and which browser defense exists?", "option_a": "Hacking via IDE tools; fixed by updating the IDE", "option_b": "Using Unicode characters that look like ASCII letters to create lookalike domains; browsers mitigate this by displaying punycode for suspicious mixed-script domains", "option_c": "A SQL injection via URL; fixed by WAF", "option_d": "An attack using identical URL paths; fixed by HTTPS", "correct_answer": "B", "explanation": "Unicode homograph attacks can make paypal.com look identical to paypal.com.", "difficulty": "hard", "category": "URL"},
    {"id": 75, "question": "How do attackers abuse Google's own infrastructure for phishing?", "option_a": "They hack Google servers directly", "option_b": "They use legitimate Google services (Forms, Sites, Drive) to host phishing pages that pass URL filters since google.com is trusted", "option_c": "They buy Google ads to redirect users", "option_d": "They exploit Google Translate to mask phishing URLs", "correct_answer": "B", "explanation": "Phishing pages on google.com bypass URL filters.", "difficulty": "hard", "category": "URL"},
    {"id": 76, "question": "What is 'adversary-in-the-middle phishing' (AiTM) using Evilginx?", "option_a": "A man-in-the-middle hardware attack", "option_b": "A phishing technique using a reverse proxy to intercept credentials AND session cookies in real time, bypassing MFA", "option_c": "A DNS poisoning attack", "option_d": "A keystroke logging method", "correct_answer": "B", "explanation": "AiTM proxies capture both passwords and session cookies, defeating MFA.", "difficulty": "hard", "category": "email"},
    {"id": 77, "question": "What is 'polyglot file' technique in email attachments?", "option_a": "An attachment in multiple languages", "option_b": "A file that is simultaneously valid in two formats (e.g., a PDF that is also a JavaScript file), used to evade security scanners", "option_c": "A multilingual phishing email", "option_d": "A file that changes language based on location", "correct_answer": "B", "explanation": "Polyglot files evade scanners that only check one file type.", "difficulty": "hard", "category": "email"},
    {"id": 78, "question": "What is 'living off the land' (LotL) technique?", "option_a": "Phishing attacks targeting farmers", "option_b": "Using legitimate system tools (PowerShell, WMI, certutil) already present on the victim's machine to execute malicious actions, evading detection", "option_c": "Ransomware targeting agricultural systems", "option_d": "Using open-source tools for phishing", "correct_answer": "B", "explanation": "LotL uses built-in tools to avoid triggering security alerts.", "difficulty": "hard", "category": "email"},
    {"id": 79, "question": "What is 'callback phishing' (TOAD)?", "option_a": "Phishing via voicemail only", "option_b": "An email containing no malicious links - instead directing victims to call a phone number where live social engineers complete the attack", "option_c": "Phishing that calls you back after clicking a link", "option_d": "Automated robocall phishing", "correct_answer": "B", "explanation": "TOAD uses live phone calls with social engineers.", "difficulty": "hard", "category": "email"},
    {"id": 80, "question": "What is 'SS7 protocol' and why is it vulnerable to interception?", "option_a": "A 5G encryption protocol; vulnerable to quantum attacks", "option_b": "A 1970s-era telecom signaling protocol with no built-in authentication - attackers with SS7 access can redirect calls/SMS worldwide", "option_c": "A SIM card protocol; vulnerable only in older phones", "option_d": "A Wi-Fi protocol; vulnerable to MITM attacks", "correct_answer": "B", "explanation": "SS7 was designed without security in mind.", "difficulty": "hard", "category": "sms"},
    {"id": 81, "question": "What is 'IMSI catching' (Stingray attack) in mobile security?", "option_a": "Hacking IMSI databases", "option_b": "Using a fake mobile base station device to intercept communications of nearby phones", "option_c": "A SIM swap variant", "option_d": "An attack on IMSI numbers in databases", "correct_answer": "B", "explanation": "Stingrays pretend to be cell towers to intercept mobile traffic.", "difficulty": "hard", "category": "sms"},
    {"id": 82, "question": "What is 'deepfake vishing' and why is it a growing threat?", "option_a": "Fake social media profiles using deep learning", "option_b": "Using AI-generated voice clones of trusted individuals (executives, family members) to conduct voice phishing attacks that are nearly indistinguishable from real calls", "option_c": "Deep web phishing via voice chat", "option_d": "AI-generated email phishing", "correct_answer": "B", "explanation": "Deepfake audio makes vishing calls nearly impossible to detect.", "difficulty": "hard", "category": "social"},
    {"id": 83, "question": "What is 'pig butchering' (Sha Zhu Pan) scam?", "option_a": "A food industry cyberattack", "option_b": "A long-term investment fraud where attackers build romantic or friendship trust with victims over weeks or months before convincing them to invest in fake crypto platforms", "option_c": "A social media hacking method", "option_d": "A ransomware targeting butcher shops", "correct_answer": "B", "explanation": "Pig butchering combines romance scams with investment fraud.", "difficulty": "hard", "category": "social"},
    {"id": 84, "question": "What is 'MITRE ATT&CK' and how is it used in phishing defense?", "option_a": "An attack simulation game", "option_b": "A knowledge base of adversary tactics and techniques based on real-world observations - used to map phishing TTPs and identify defensive gaps", "option_c": "A penetration testing tool", "option_d": "A government cybersecurity regulation", "correct_answer": "B", "explanation": "ATT&CK framework documents how attackers operate.", "difficulty": "hard", "category": "general"},
    {"id": 85, "question": "What is 'access broker' in the cybercrime ecosystem?", "option_a": "A legitimate IT service", "option_b": "Criminals who use phishing to gain initial access to organizations, then sell that access to ransomware groups or other attackers on dark web forums", "option_c": "A penetration testing firm", "option_d": "A cybersecurity recruiter", "correct_answer": "B", "explanation": "Access brokers sell initial network access to other criminals.", "difficulty": "hard", "category": "general"},
    {"id": 86, "question": "What makes 'AI-generated spear phishing' emails harder to detect?", "option_a": "They are sent faster", "option_b": "AI can generate perfectly grammatical, highly personalized emails using OSINT data at scale - eliminating the spelling errors that were red flags", "option_c": "They bypass all email filters technically", "option_d": "They come from verified domains automatically", "correct_answer": "B", "explanation": "AI eliminates the grammar/spelling red flags humans relied on.", "difficulty": "hard", "category": "email"},
    {"id": 87, "question": "In the 'Cialdini principles of influence', which combination is most weaponized in phishing?", "option_a": "Liking + Commitment", "option_b": "Authority + Scarcity + Social Proof + Urgency - used simultaneously to overwhelm critical thinking", "option_c": "Reciprocity only", "option_d": "Consistency + Liking", "correct_answer": "B", "explanation": "Phishing combines multiple psychological principles for maximum manipulation.", "difficulty": "hard", "category": "social"},
    {"id": 88, "question": "What is 'USB drop attack' and what makes it effective?", "option_a": "Dropping USB prices to steal market share", "option_b": "Leaving malware-infected USB drives in target locations - effective because human curiosity leads people to plug them in", "option_c": "Physically destroying USB drives", "option_d": "A network attack via USB adapters", "correct_answer": "B", "explanation": "Curiosity and helpfulness make USB drops surprisingly effective.", "difficulty": "hard", "category": "social"},
    {"id": 89, "question": "What is 'browser-in-the-browser' (BitB) attack in phishing?", "option_a": "Running a browser inside a virtual machine", "option_b": "Simulating a fake browser popup window within a webpage using HTML/CSS to mimic OAuth login popups, tricking users into entering credentials", "option_c": "Hacking via browser extensions", "option_d": "Injecting code into the browser's memory", "correct_answer": "B", "explanation": "BitB creates fake popups that look like real OAuth windows.", "difficulty": "hard", "category": "URL"},
    {"id": 90, "question": "What is 'PhaaS' (Phishing-as-a-Service)?", "option_a": "A legitimate phishing awareness training platform", "option_b": "A cybercriminal business model where ready-made phishing kits, infrastructure, and customer support are sold to non-technical attackers", "option_c": "A government anti-phishing service", "option_d": "A PhD course on phishing", "correct_answer": "B", "explanation": "PhaaS lowers the barrier for launching phishing attacks.", "difficulty": "hard", "category": "general"},
]

@app.route('/api/quiz', methods=['GET'])
def get_quiz_questions():
    limit = int(request.args.get('limit', 10))
    difficulty = request.args.get('difficulty', '')
    category = request.args.get('category', '')
    
    questions = quiz_questions_db
    if difficulty:
        questions = [q for q in questions if q['difficulty'] == difficulty]
    if category:
        questions = [q for q in questions if q['category'] == category]
    
    import random
    questions = random.sample(questions, min(limit, len(questions)))
    
    return jsonify({"success": True, "questions": questions, "total": len(quiz_questions_db)})

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "models_loaded": url_model is not None and text_model is not None, "timestamp": datetime.now().isoformat()})

# =============================================
# OTP & AUTO-LOGIN ENDPOINTS
# =============================================

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets

OTP_EXPIRY = 60

def send_otp_email(email, otp, purpose='login'):
    smtp_email = os.environ.get('SMTP_EMAIL', '')
    smtp_password = os.environ.get('SMTP_PASSWORD', '')
    
    if not smtp_email or not smtp_password:
        return False, "SMTP not configured"
    
    if purpose == 'password_reset':
        subject = 'PhishGuard AI - Password Reset Code'
        subtitle = 'Password Reset Request'
        description = 'Enter this code to reset your password:'
    else:
        subject = 'Your PhishGuard AI OTP Code'
        subtitle = 'Secure Authentication'
        description = 'Your one-time verification code:'
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = smtp_email
        msg['To'] = email
        
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0f; margin: 0; padding: 20px; }}
                .container {{ max-width: 500px; margin: 0 auto; background: linear-gradient(145deg, #1a1a2e, #16213e); border-radius: 20px; padding: 40px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(0, 255, 136, 0.1); }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .logo {{ font-size: 28px; font-weight: bold; color: #00ff88; text-shadow: 0 0 20px rgba(0, 255, 136, 0.5); }}
                .subtitle {{ color: #888; font-size: 14px; margin-top: 5px; }}
                .otp-box {{ background: rgba(0, 255, 136, 0.1); border: 2px solid #00ff88; border-radius: 15px; padding: 25px; text-align: center; margin: 30px 0; }}
                .otp-code {{ font-size: 42px; font-weight: bold; color: #00ff88; letter-spacing: 12px; text-shadow: 0 0 30px rgba(0, 255, 136, 0.8); }}
                .timer {{ color: #ff6b6b; font-size: 14px; margin-top: 15px; }}
                .warning {{ color: #ffaa00; font-size: 12px; text-align: center; margin-top: 20px; }}
                .footer {{ text-align: center; color: #555; font-size: 11px; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🛡️ PhishGuard AI</div>
                    <div class="subtitle">{subtitle}</div>
                </div>
                <p style="color: #ccc; text-align: center;">{description}</p>
                <div class="otp-box">
                    <div class="otp-code">{otp}</div>
                    <div class="timer">⏱️ Expires in {OTP_EXPIRY} seconds</div>
                </div>
                <div class="warning">⚠️ Never share this code with anyone. Our team will never ask for it.</div>
                <div class="footer">© 2026 PhishGuard AI - Advanced Phishing Detection</div>
            </div>
        </body>
        </html>
        '''
        
        text_content = f'''PhishGuard AI - {subject}

Your verification code is: {otp}

This code expires in {OTP_EXPIRY} seconds.

Never share this code with anyone.
'''
        
        msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.sendmail(smtp_email, email, msg.as_string())
        server.quit()
        return True, "OTP sent"
    except Exception as e:
        return False, str(e)

def send_demo_otp(email, otp):
    print("\n" + "="*50)
    print("  [DEMO MODE] OTP FOR TESTING")
    print("="*50)
    print(f"  To: {email}")
    print(f"  OTP: {otp}")
    print(f"  Expires in: {OTP_EXPIRY} seconds")
    print("="*50 + "\n")
    return True, "Demo OTP (check console)"

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email or '@' not in email:
        return jsonify({'success': False, 'error': 'Invalid email address'}), 400
    
    if not db_module.get_user_by_email(email):
        return jsonify({'success': False, 'error': 'Email not registered. Please register first.'}), 400
    
    otp = ''.join(secrets.choice('0123456789') for _ in range(6))
    db_module.save_otp(email, otp, OTP_EXPIRY)
    
    smtp_email = os.environ.get('SMTP_EMAIL', '')
    smtp_password = os.environ.get('SMTP_PASSWORD', '')
    
    if smtp_email and smtp_password:
        success, message = send_otp_email(email, otp)
        if not success:
            return jsonify({'success': False, 'error': f'Failed to send OTP: {message}. Check SMTP configuration.'}), 500
    else:
        success, message = send_demo_otp(email, otp)
        print(f"[DEMO MODE] OTP for {email}: {otp}")
    
    return jsonify({
        'success': True,
        'message': 'OTP sent to your email',
        'expires_in': OTP_EXPIRY
    })

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    
    if not email or not otp:
        return jsonify({'success': False, 'error': 'Email and OTP required'}), 400
    
    result = db_module.verify_otp(email, otp)
    
    if result['valid']:
        user = db_module.get_user_by_email(email)
        if user:
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            db_module.update_last_login(user['id'])
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'username': user['username'],
                    'full_name': user['full_name']
                }
            })
    
    return jsonify({
        'success': False,
        'error': result.get('error', 'Invalid OTP'),
        'attempts_left': result.get('attempts_left', 0)
    }), 401

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email or '@' not in email:
        return jsonify({'success': False, 'error': 'Invalid email address'}), 400
    
    user = db_module.get_user_by_email(email)
    if not user:
        return jsonify({'success': False, 'error': 'Email not registered. Please register first.'}), 400
    
    otp = ''.join(secrets.choice('0123456789') for _ in range(6))
    db_module.save_otp(email, otp, OTP_EXPIRY)
    
    smtp_email = os.environ.get('SMTP_EMAIL', '')
    smtp_password = os.environ.get('SMTP_PASSWORD', '')
    
    if smtp_email and smtp_password:
        success, message = send_otp_email(email, otp, purpose='password_reset')
        if not success:
            return jsonify({'success': False, 'error': f'Failed to send OTP: {message}'}), 500
    else:
        print(f"[DEMO MODE] Password Reset OTP for {email}: {otp}")
    
    return jsonify({
        'success': True,
        'message': 'Password reset code sent to your email',
        'expires_in': OTP_EXPIRY
    })

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not email or not otp or not new_password:
        return jsonify({'success': False, 'error': 'Email, OTP, and new password are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    result = db_module.verify_otp(email, otp)
    
    if not result['valid']:
        return jsonify({
            'success': False,
            'error': result.get('error', 'Invalid OTP'),
            'attempts_left': result.get('attempts_left', 0)
        }), 401
    
    import hashlib
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    
    with db_module.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
    
    return jsonify({
        'success': True,
        'message': 'Password reset successfully! Please login with your new password.'
    })

@app.route('/api/auto-login-check', methods=['POST'])
def auto_login_check():
    email = session.get('user_email')
    print(f"[DEBUG] Auto-login check: session email = {email}")
    if email:
        user = db_module.get_user_by_email(email)
        if user:
            print(f"[DEBUG] Auto-login found user: {email}")
            return jsonify({
                'success': True,
                'found': True,
                'email': email
            })
    print("[DEBUG] Auto-login: no saved session")
    return jsonify({'success': True, 'found': False})

# Update database module to include update_last_login
import database as db_module
if not hasattr(db_module, 'update_last_login'):
    def update_last_login(user_id):
        import time
        with db_module.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (int(time.time()), user_id))
    db_module.update_last_login = update_last_login

db_module.init_otp_table()

# =============================================
# AI CHATBOT (OpenAI Powered - GPT-4o-mini)
# =============================================

def chatbot_response(user_input):
    """Generate response using OpenAI GPT-4o-mini"""
    import openai
    import os
    
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": """You are PhishGuard AI, a helpful and friendly cybersecurity assistant chatbot.

Your expertise includes:
- Phishing detection and prevention advice
- Explaining cyber threats (malware, ransomware, scams, trojans, etc.)
- Password and account security best practices
- Safe browsing and email security tips
- How to recognize and report scams
- General technology questions related to cybersecurity

Guidelines:
- Be friendly, helpful, and concise
- Use simple language for everyone to understand
- Prioritize user safety in all advice
- Suggest actionable steps when possible
- You can explain technical concepts in simple terms"""
            },
            {
                "role": "user",
                "content": user_input
            }
        ],
        temperature=0.7,
        max_tokens=500
    )
    
    return response.choices[0].message.content

@app.route('/api/chat', methods=['POST'])
def ai_chat():
    data = request.get_json()
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Check for URL in message - provide context
    url_detected = None
    if 'http://' in message.lower() or 'https://' in message.lower() or 'www.' in message.lower():
        url_match = None
        for pattern in [r'https?://[^\s]+', r'www\.[^\s]+']:
            import re
            match = re.search(pattern, message, re.I)
            if match:
                url_detected = match.group()
                break
        
        if url_detected:
            # Add context that URL was detected
            message = f"User mentioned this URL: {url_detected}\n\nQuestion: {message}"
    
    # Check for OpenAI API key
    openai_api_key = os.environ.get('OPENAI_API_KEY', '')
    
    if openai_api_key:
        try:
            bot_response = chatbot_response(message)
            
            # Add helpful tip if URL was detected
            if url_detected:
                bot_response += "\n\n💡 Tip: Use our URL Analyzer above to get an instant AI-powered verdict on that link!"
            
            return jsonify({
                'success': True,
                'response': bot_response,
                'source': 'openai'
            })
            
        except Exception as e:
            print(f"[ERROR] OpenAI API error: {e}")
            return jsonify({
                'success': True,
                'response': "I'm having trouble connecting to my AI brain right now. Please try again! In the meantime, you can use our phishing detection tools above.",
                'source': 'error'
            }), 200
    else:
        # Fallback responses if no API key
        message_lower = message.lower()
        
        # Check if URL was mentioned
        has_url = 'http' in message_lower or 'www.' in message_lower
        
        if any(word in message_lower for word in ['hi', 'hello', 'hey']):
            response_text = "Hello! 👋 I'm PhishGuard AI, your cybersecurity assistant.\n\nI can help you with:\n\n🔍 Phishing detection advice\n❓ Cybersecurity questions\n💡 Safety tips\n🛡️ Account protection\n\nWhat would you like help with?"
        
        elif 'phishing' in message_lower or 'phish' in message_lower:
            response_text = "🎣 Phishing is a cyber attack where attackers trick you into revealing sensitive information.\n\nCommon methods:\n• Fake emails from banks or tech companies\n• Malicious links in messages\n• Imposter websites\n\nProtection:\n✅ Verify sender email addresses\n✅ Don't click suspicious links\n✅ Use our URL/Email analyzers above!"
        
        elif 'password' in message_lower or 'hack' in message_lower:
            response_text = "🔐 Password Security:\n\n✅ Use passphrases (CorrectHorseBatteryStaple)\n✅ Use a password manager\n✅ Different passwords for each account\n✅ Enable 2FA\n\n❌ Never share passwords\n❌ Don't use personal info in passwords"
        
        elif 'virus' in message_lower or 'malware' in message_lower or 'ransomware' in message_lower:
            response_text = "🦠 Cyber Threats:\n\n🔴 Ransomware - Encrypts files, demands payment\n🔴 Trojans - Hidden in downloads\n🔴 Spyware - Monitors activity secretly\n🔴 Adware - Shows unwanted ads\n\nPrevention:\n✅ Keep software updated\n✅ Don't download from unknown sources\n✅ Use antivirus software"
        
        elif 'safe' in message_lower or 'protect' in message_lower or 'tip' in message_lower:
            response_text = "🛡️ Security Tips:\n\n1️⃣ Verify all sender addresses\n2️⃣ Hover over links before clicking\n3️⃣ Enable two-factor authentication\n4️⃣ Use strong, unique passwords\n5️⃣ Keep devices and software updated\n6️⃣ Never share OTP or passwords"
        
        elif 'email' in message_lower or 'sms' in message_lower or 'message' in message_lower:
            response_text = "📧 Analysis Tips:\n\nYou can analyze:\n• Suspicious URLs → Use URL Analyzer\n• Phishing emails → Use Email Analyzer\n• SMS scams → Use Message Scanner\n\nJust paste the content and get instant results!"
        
        elif 'scam' in message_lower or 'fake' in message_lower:
            response_text = "⚠️ Scam Detection:\n\nRed flags:\n🚩 Urgent or threatening language\n🚩 Too good to be true offers\n🚩 Requests for personal info\n🚩 Suspicious links or attachments\n\nReport scams at:\n📌 reportfraud.ftc.gov"
        
        else:
            response_text = "🤖 I'm PhishGuard AI!\n\nI can help with:\n• Phishing and scam detection\n• Password security\n• Safe browsing tips\n• Cybersecurity threats\n• Account protection\n\nOr use our analyzers above for instant detection!"
        
        if has_url:
            response_text += "\n\n💡 I noticed a URL in your message! Use our URL Analyzer above to check if it's safe."
        
        return jsonify({
            'success': True,
            'response': response_text,
            'source': 'fallback'
        })

# =============================================
# PROFILE IMAGE UPLOAD
# =============================================
@app.route('/api/upload-profile', methods=['POST'])
@login_required
def upload_profile():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image provided'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No image selected'}), 400
    
    user = get_current_user()
    if not user:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Create uploads directory
    upload_dir = os.path.join(BASE_DIR, 'static', 'uploads', 'profiles')
    os.makedirs(upload_dir, exist_ok=True)
    
    # Generate unique filename
    import time
    filename = f"user_{user['id']}_{int(time.time())}.jpg"
    filepath = os.path.join(upload_dir, filename)
    
    # Save and resize image
    try:
        from PIL import Image
        img = Image.open(file)
        img = img.convert('RGB')
        img.thumbnail((300, 300))
        img.save(filepath, 'JPEG', quality=85)
        
        # Update database
        image_url = f'/static/uploads/profiles/{filename}'
        db_module.update_profile_image(user['id'], image_url)
        
        return jsonify({
            'success': True,
            'image_url': image_url
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Update database module
if not hasattr(db_module, 'update_profile_image'):
    def update_profile_image(user_id, image_url):
        with db_module.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET profile_image = ? WHERE id = ?', (image_url, user_id))
    db_module.update_profile_image = update_profile_image

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  PHISHGUARD - ADVANCED AI PHISHING DETECTION")
    print("="*50 + "\n")
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
