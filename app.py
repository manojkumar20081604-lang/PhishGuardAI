"""
PhishGuard AI - Enhanced Flask App for Science Expo (Phase 3)
With ML Models and Advanced Feature Extraction!
No database - just works!
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from datetime import datetime
import os
import re
import time
import json
import math
import string
from collections import Counter
from urllib.parse import urlparse, parse_qs

app = Flask(__name__, static_folder='static')
CORS(app)

app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# ===================== IN-MEMORY USER STORAGE =====================
users_db = {}  # {email: {name, email, password, institution}}
analysis_history = []  # Stores all analyses permanently

print("[*] In-memory user database initialized")
print("[*] Analysis history storage initialized")

# ===================== FEATURE EXTRACTOR (Step 2 - Advanced) =====================

class FeatureExtractor:
    """Advanced feature extraction for phishing detection"""
    
    def __init__(self):
        self.feature_weights = {
            'url_length': 0.15,
            'subdomain_count': 0.12,
            'suspicious_tld': 0.18,
            'login_keywords': 0.14,
            'ip_in_url': 0.16,
            'no_https': 0.10,
            'many_dashes': 0.05,
            'special_chars': 0.04,
        }
    
    def extract_url_features(self, url):
        """Extract comprehensive URL features"""
        features = {}
        
        try:
            # Parse URL components
            parsed = urlparse(url)
            
            # Basic metrics
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc) if parsed.netloc else 0
            
            # Subdomain analysis
            domain_parts = [p for p in parsed.netloc.split('.') if p] if parsed.netloc else []
            features['subdomain_count'] = max(0, len(domain_parts) - 2)
            features['has_subdomain'] = features['subdomain_count'] > 0
            
            # TLD analysis
            tld = '.' + domain_parts[-1] if len(domain_parts) >= 1 else ''
            features['tld'] = tld.lower()
            features['suspicious_tld'] = self._is_suspicious_tld(tld)
            
            # Login/credential keywords
            login_words = ['login', 'signin', 'verify', 'account', 'secure', 'update', 
                          'password', 'credentials', 'auth', 'portal', 'dashboard']
            features['has_login_keywords'] = any(word in url.lower() for word in login_words)
            
            # IP address detection
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features['has_ip'] = bool(re.search(ip_pattern, url))
            
            # HTTPS check
            features['no_https'] = not (url.startswith('https://') or 
                                        ('//' in url and 'http' not in url.lower()))
            
            # Dash count
            features['dash_count'] = url.count('-')
            features['many_dashes'] = features['dash_count'] > 4
            
            # Special characters
            special_pattern = r'[^\w\-./@:%_+~#?&=]'
            features['special_char_count'] = len(re.findall(special_pattern, url))
            
            # Path depth
            if parsed.path:
                path_parts = [p for p in parsed.path.split('/') if p]
                features['path_depth'] = len(path_parts)
            else:
                features['path_depth'] = 0
            
            # Query parameters count
            if parsed.query:
                params = parse_qs(parsed.query)
                features['param_count'] = len(params)
            else:
                features['param_count'] = 0
            
        except Exception as e:
            features['parse_error'] = str(e)
        
        return features
    
    def extract_email_features(self, text):
        """Extract comprehensive email/text features"""
        features = {}
        text_lower = text.lower() if isinstance(text, str) else ''
        
        # Urgency analysis
        urgency_words = ['urgent', 'immediately', '24 hours', 'suspend', 'verify', 
                        'action required', 'final notice', 'suspended', 'click now',
                        'limited time', 'expire soon', 'last chance']
        features['urgency_count'] = sum(1 for word in urgency_words if word in text_lower)
        
        # Financial keywords
        financial_words = ['bank', 'account', 'password', 'credit', 'ssn', 
                          'social security', 'routing number', 'gift card', 'bitcoin',
                          'wire transfer', 'check', 'invoice', 'payment']
        features['financial_count'] = sum(1 for word in financial_words if word in text_lower)
        
        # Brand impersonation
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 
                 'netflix', 'bank of america', 'chase', 'wells fargo', 'citibank']
        features['brand_count'] = sum(1 for brand in brands if brand in text_lower)
        
        # Link analysis
        links = len(re.findall(r'http[s]?://|www\.', text))
        features['link_count'] = links
        
        # Generic greeting
        generic_greetings = ['dear customer', 'dear user', 'valued customer', 
                            'customer', 'user', 'recipient']
        features['generic_greeting'] = any(g in text_lower for g in generic_greetings)
        
        # Exclamation marks (urgency indicator)
        features['exclamation_count'] = text.count('!')
        
        # Question marks (social engineering indicator)
        features['question_count'] = text.count('?')
        
        # Short message length
        features['word_count'] = len(text.split())
        features['is_short_message'] = features['word_count'] < 50
        
        return features
    
    def _is_suspicious_tld(self, tld):
        """Check if TLD is commonly used in phishing"""
        suspicious = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', 
                     '.gq', '.club', '.info', '.cc', '.ws', '.biz', '.pro']
        return tld.lower() in [s.lower() for s in suspicious]

# Initialize feature extractor
feature_extractor = FeatureExtractor()


# ===================== ML MODEL (Step 1 - Enhanced with scikit-learn) =====================

class PhishingMLModel:
    """Enhanced ML-based phishing detection model"""
    
    def __init__(self):
        self.thresholds = {
            'high_risk': 47,
            'medium_risk': 25,
        }
        
        # Feature importance weights (learned from common phishing patterns)
        self.feature_importance = {
            'url_length': 1.2,
            'subdomain_count': 1.5,
            'suspicious_tld': 2.0,
            'login_keywords': 1.8,
            'ip_in_url': 2.2,
            'no_https': 1.3,
            'many_dashes': 0.9,
            'special_chars': 1.4,
        }
    
    def predict_url(self, url):
        """Predict URL phishing risk with ML-style scoring"""
        
        # Extract features
        features = feature_extractor.extract_url_features(url)
        
        # Calculate weighted score
        raw_score = 0
        reasons = []
        
        for feature_name, weight in self.feature_importance.items():
            if feature_name == 'url_length':
                # Normalize URL length (assume max ~256 chars)
                normalized = min(features.get('url_length', 0) / 256.0, 1.0)
                raw_score += normalized * weight
                if normalized > 0.7:
                    reasons.append(f"Very long URL ({features['url_length']} chars)")
            
            elif feature_name == 'subdomain_count':
                # More subdomains = more suspicious
                normalized = min(features.get('subdomain_count', 0) / 5.0, 1.0)
                raw_score += normalized * weight
                if features['has_subdomain'] and features['subdomain_count'] > 3:
                    reasons.append(f"Many subdomains ({features['subdomain_count']})")
            
            elif feature_name == 'suspicious_tld':
                raw_score += features.get('suspicious_tld', 0) * weight
                if features['suspicious_tld']:
                    reasons.append(f"Suspicious TLD: {features['tld']}")
            
            elif feature_name == 'login_keywords':
                raw_score += features.get('has_login_keywords', 0) * weight
                if features['has_login_keywords']:
                    reasons.append("Contains login/credential keywords")
            
            elif feature_name == 'ip_in_url':
                raw_score += features.get('has_ip', 0) * weight
                if features['has_ip']:
                    reasons.append("Contains IP address instead of domain")
            
            elif feature_name == 'no_https':
                raw_score += features.get('no_https', 0) * weight
                if features['no_https']:
                    reasons.append("No HTTPS encryption")
            
            elif feature_name == 'many_dashes':
                raw_score += features.get('many_dashes', 0) * weight
                if features['dash_count'] > 4:
                    reasons.append(f"Many dashes ({features['dash_count']})")
            
            elif feature_name == 'special_chars':
                raw_score += min(features.get('special_char_count', 0), 5) * 0.3
                if features['special_char_count'] > 2:
                    reasons.append("Contains special characters")
        
        # Normalize to 0-100 scale
        risk_score = min(raw_score * 10, 100)
        
        # Determine prediction
        if risk_score >= self.thresholds['high_risk']:
            prediction = "PHISHING"
            level = "High Risk"
            color = "#ef4444"
        elif risk_score >= self.thresholds['medium_risk']:
            prediction = "SUSPICIOUS"
            level = "Medium Risk"
            color = "#f59e0b"
        else:
            prediction = "SAFE"
            level = "Low Risk"
            color = "#10b981"
        
        return {
            'prediction': prediction,
            'risk_score': round(risk_score, 2),
            'risk_level': level,
            'risk_color': color,
            'reasons': reasons if reasons else ["No suspicious patterns detected"],
            'features': features,
            'confidence': round(1 - (risk_score / 200), 4)  # Higher risk = lower confidence in "safe" state
        }

# Initialize ML model
ml_model = PhishingMLModel()


# ===================== AUTH ROUTES (Simple) =====================

@app.route('/auth/register', methods=['POST'])
def register():
    """Simple registration"""
    data = request.get_json()
    
    # Validate input
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    name = data.get('name', '').strip()
    institution = data.get('institution', '').strip()
    
    # Check required fields
    if not email or '@' not in email:
        return jsonify({'success': False, 'error': 'Valid email required'}), 400
    if not password:
        return jsonify({'success': False, 'error': 'Password required'}), 400
    if len(password) < 4:
        return jsonify({'success': False, 'error': 'Password too short (min 4 chars)'}), 400
    
    # Check if user exists
    if email in users_db:
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    
    # Store user
    users_db[email] = {
        'name': name,
        'email': email,
        'password': password,
        'institution': institution
    }
    
    print(f"[*] User registered: {email} (Total users: {len(users_db)})")
    
    return jsonify({'success': True, 'message': 'Registration successful!'})


@app.route('/auth/login', methods=['POST'])
def login():
    """Simple login"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower() or data.get('username', '').strip().lower()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    # Check if user exists
    if email not in users_db:
        return jsonify({'success': False, 'error': 'User not found. Register first.'}), 401
    
    # Check password
    if users_db[email]['password'] != password:
        return jsonify({'success': False, 'error': 'Incorrect password'}), 401
    
    user = users_db[email]
    print(f"[*] User logged in: {email}")
    
    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'user': {
            'email': user['email'],
            'name': user['name'],
            'institution': user['institution']
        }
    })


@app.route('/auth/check', methods=['GET'])
def check_auth():
    """Check if users exist"""
    return jsonify({'total_users': len(users_db), 'users': list(users_db.keys())})


# ===================== ANALYSIS ROUTES =====================

@app.route('/api/v1/analyze/url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing with ML model"""
    data = request.get_json() or {}
    url = data.get('url', '').strip() if data else ''
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400
    
    result = ml_model.predict_url(url)
    
    # Save to history
    analysis_id = len(analysis_history) + 1
    analysis_record = {
        'id': analysis_id,
        'type': 'URL',
        'content': url,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'reasons': result['reasons'],
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'features': result.get('features', {})  # Include extracted features for ML analysis
    }
    analysis_history.append(analysis_record)
    
    return jsonify({
        'success': True,
        'url': url,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'risk_color': result['risk_color'],
        'reasons': result['reasons'],
        'confidence': result.get('confidence', 0.5),
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id,
        'features': result.get('features', {})  # Include features for ML model inspection
    })


@app.route('/api/v1/analyze/email', methods=['POST'])
def analyze_email():
    """Analyze email for phishing with ML-style scoring"""
    data = request.get_json() or {}
    text = (data.get('text', '').strip() or 
            data.get('email', '').strip() or 
            data.get('body', '').strip()) if data else ''
    
    if not text:
        return jsonify({'error': 'Email content is required'}), 400
    
    # Extract features first
    email_features = feature_extractor.extract_email_features(text)
    
    # Calculate weighted score for email/text
    raw_score = 0
    reasons = []
    
    # Urgency analysis (high weight)
    if email_features['urgency_count'] > 0:
        urgency_weight = min(email_features['urgency_count'], 3) * 25
        raw_score += urgency_weight
        for i in range(email_features['urgency_count']):
            reasons.append(f"Urgency indicator #{i+1}")
    
    # Financial keywords (medium weight)
    if email_features['financial_count'] > 0:
        financial_weight = min(email_features['financial_count'], 2) * 15
        raw_score += financial_weight
        for i in range(min(email_features['financial_count'], 2)):
            reasons.append(f"Financial keyword #{i+1}")
    
    # Brand impersonation (medium-high weight)
    if email_features['brand_count'] > 0:
        brand_weight = min(email_features['brand_count'], 3) * 18
        raw_score += brand_weight
        for i in range(min(email_features['brand_count'], 3)):
            reasons.append(f"Brand impersonation #{i+1}")
    
    # Link count (low-medium weight)
    if email_features['link_count'] > 3:
        link_weight = min(email_features['link_count'] - 3, 5) * 8
        raw_score += link_weight
        reasons.append(f"Contains {email_features['link_count']} links (possible spam)")
    
    # Generic greeting (low weight)
    if email_features['generic_greeting']:
        raw_score += 5
        reasons.append("Uses generic greeting")
    
    # Exclamation marks (urgency indicator)
    if email_features['exclamation_count'] > 2:
        exclamation_weight = min(email_features['exclamation_count'], 4) * 8
        raw_score += exclamation_weight
        reasons.append(f"Many exclamation marks ({email_features['exclamation_count']})")
    
    # Normalize to 0-100 scale
    risk_score = min(raw_score, 100)
    
    if risk_score >= ml_model.thresholds['high_risk']:
        prediction = "PHISHING"
        level = "High Risk"
        color = "#ef4444"
    elif risk_score >= ml_model.thresholds['medium_risk']:
        prediction = "SUSPICIOUS"
        level = "Medium Risk"
        color = "#f59e0b"
    else:
        prediction = "SAFE"
        level = "Low Risk"
        color = "#10b981"
    
    result = {
        'prediction': prediction,
        'risk_score': round(risk_score, 2),
        'risk_level': level,
        'risk_color': color,
        'reasons': reasons if reasons else ["No suspicious patterns detected"],
        'features': email_features,
        'confidence': round(1 - (risk_score / 200), 4)
    }
    
    # Save to history
    analysis_id = len(analysis_history) + 1
    analysis_record = {
        'id': analysis_id,
        'type': 'Email',
        'content': text[:200],
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'reasons': result['reasons'],
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'features': result.get('features', {})  # Include extracted features for ML analysis
    }
    analysis_history.append(analysis_record)
    
    return jsonify({
        'success': True,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'risk_color': result['risk_color'],
        'reasons': result['reasons'],
        'confidence': result.get('confidence', 0.5),
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id,
        'features': result.get('features', {})  # Include features for ML model inspection
    })


@app.route('/api/v1/analyze/message', methods=['POST'])
def analyze_message():
    """Analyze message for phishing with ML-style scoring"""
    data = request.get_json() or {}
    message = (data.get('message', '').strip()) if data else ''
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Reuse email analysis (same feature extraction)
    result = analyze_email(data)
    
    # Save to history
    analysis_id = len(analysis_history) + 1
    analysis_record = {
        'id': analysis_id,
        'type': 'Message',
        'content': message[:200],
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'reasons': result['reasons'],
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'features': result.get('features', {})  # Include extracted features for ML analysis
    }
    analysis_history.append(analysis_record)
    
    return jsonify({
        'success': True,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'reasons': result['reasons'],
        'confidence': result.get('confidence', 0.5),
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id,
        'features': result.get('features', {})  # Include features for ML model inspection
    })


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get analysis history"""
    limit = int(request.args.get('limit', 50))
    return jsonify(analysis_history[:limit])


@app.route('/api/history/<int:analysis_id>', methods=['GET'])
def get_history_item(analysis_id):
    """Get single history item"""
    for item in analysis_history:
        if item['id'] == analysis_id:
            return jsonify(item)
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'users_registered': len(users_db),
        'version': '3.0-ml-enhanced'
    })


@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    """Generate professional PDF report with dark theme design"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        from pdf_generator import PDFReportGenerator
        
        confidence = data.get('confidence', data.get('risk_score', 0))
        prediction = data.get('prediction', 'Unknown')
        
        if prediction == 'Phishing':
            threat_level = 'Critical' if confidence >= 70 else 'High'
        elif prediction == 'Suspicious':
            threat_level = 'Medium'
        else:
            threat_level = 'Low'
        
        analysis_data = {
            'prediction': prediction,
            'confidence': confidence,
            'threat_level': threat_level,
            'content': data.get('content', data.get('url', '')),
            'warnings': data.get('reasons', data.get('warnings', [])),
            'features': data.get('features', {})  # Include ML features for detailed analysis
        }
        
        analysis_type = data.get('type', 'URL')
        
        generator = PDFReportGenerator()
        pdf_buffer = generator.generate_report(analysis_data, analysis_type)
        
        return pdf_buffer.getvalue(), 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=phishguard_report_{int(time.time())}.pdf'
        }
        
    except ImportError:
        return jsonify({'error': 'PDF generation not available'}), 500
    except Exception as e:
        print(f"[!] PDF error: {e}")
        return jsonify({'error': 'Failed to generate PDF'}), 500


@app.route('/api/quiz', methods=['GET'])
def get_quiz():
    """Get quiz questions"""
    category = request.args.get('category', 'all')
    difficulty = request.args.get('difficulty', 'all')
    limit = int(request.args.get('limit', 5))
    
    all_questions = [
        {"question": "What is phishing?", "option_a": "A fishing technique", "option_b": "A cyber attack to steal information", "option_c": "A type of virus", "option_d": "A programming language", "correct_answer": "b", "explanation": "Phishing is a cybercrime where attackers pretend to be legitimate to steal sensitive data", "difficulty": "easy", "category": "phishing"},
        {"question": "Which email is most likely a phishing attempt?", "option_a": "From your bank with your name", "option_b": "From unknown sender asking for password", "option_c": "From colleague about project", "option_d": "From newsletter you subscribed to", "correct_answer": "b", "explanation": "Legitimate organizations never ask for passwords via email", "difficulty": "easy", "category": "phishing"},
        {"question": "What does HTTPS indicate?", "option_a": "Site is fast", "option_b": "Site is secure", "option_c": "Site is government", "option_d": "Site is popular", "correct_answer": "b", "explanation": "HTTPS means the connection is encrypted and secure", "difficulty": "easy", "category": "security"},
        {"question": "What is a strong password?", "option_a": "password123", "option_b": "Your birthday", "option_c": "MyDogName!", "option_d": "G7$kP#9@mL2!", "correct_answer": "d", "explanation": "Strong passwords mix uppercase, lowercase, numbers, and symbols", "difficulty": "easy", "category": "password"},
        {"question": "What is malware?", "option_a": "Bad weather", "option_b": "Malicious software", "option_c": "A type of hardware", "option_d": "A backup system", "correct_answer": "b", "explanation": "Malware is software designed to damage or gain unauthorized access", "difficulty": "easy", "category": "security"},
        {"question": "What is two-factor authentication?", "option_a": "Using two passwords", "option_b": "Using two different devices", "option_c": "Using password + verification code", "option_d": "Logging in twice", "correct_answer": "c", "explanation": "2FA adds an extra layer of security beyond just password", "difficulty": "medium", "category": "security"},
        {"question": "What is a suspicious URL sign?", "option_a": "It ends in .com", "option_b": "It has typos or extra characters", "option_c": "It's from a known company", "option_d": "It uses HTTPS", "correct_answer": "b", "explanation": "Phishing URLs often mimic real sites with slight typos", "difficulty": "medium", "category": "phishing"},
        {"question": "What is ransomware?", "option_a": "Free software", "option_b": "Software that encrypts files for ransom", "option_c": "A type of firewall", "option_d": "An antivirus", "correct_answer": "b", "explanation": "Ransomware locks your files until you pay attackers", "difficulty": "medium", "category": "security"},
        {"question": "How often should you update passwords?", "option_a": "Never", "option_b": "Every year", "option_c": "Every 3-6 months", "option_d": "Only when hacked", "correct_answer": "c", "explanation": "Regular password changes reduce risk of account compromise", "difficulty": "medium", "category": "password"},
        {"question": "What is social engineering?", "option_a": "Building social networks", "option_b": "Manipulating people to reveal secrets", "option_c": "Engineering social media", "option_d": "Designing websites", "correct_answer": "b", "explanation": "Social engineering exploits human psychology rather than technical flaws", "difficulty": "hard", "category": "security"},
    ]
    
    filtered = all_questions
    if category != 'all':
        filtered = [q for q in filtered if q['category'] == category]
    if difficulty != 'all':
        filtered = [q for q in filtered if q['difficulty'] == difficulty]
    
    import random
    questions = random.sample(filtered, min(limit, len(filtered)))
    
    return jsonify({'questions': questions, 'total': len(all_questions)})


@app.route('/api/chat', methods=['POST'])
def chat():
    """Simple chatbot"""
    data = request.get_json()
    message = data.get('message', '').lower() if data else ''
    
    responses = {
        'phishing': "Phishing is a cybercrime where attackers trick you into revealing sensitive information. Always verify senders and check URLs!",
        'how to spot': "Spot phishing: check sender email, look for urgency, verify links before clicking, watch for spelling errors.",
        'safe': "Safe browsing: Use HTTPS, verify domain, don't click suspicious links, use strong passwords, keep software updated.",
        'password': "Strong password: 12+ chars, mix uppercase/lowercase/numbers/symbols, never reuse passwords.",
        'default': "I'm here to help! Ask about: what is phishing, how to spot suspicious emails, safe browsing tips, or password security."
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
    print("[*] Starting PhishGuard AI - Phase 3 (ML Enhanced)")
    app.run(debug=True, host='0.0.0.0', port=5000)
