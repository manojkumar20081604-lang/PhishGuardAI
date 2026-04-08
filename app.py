"""
PhishGuard AI - Simple Flask App for Science Expo
No database - just works!
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from datetime import datetime
import os
import re
import time

app = Flask(__name__, static_folder='static')
CORS(app)

app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# ===================== IN-MEMORY USER STORAGE =====================
users_db = {}  # {email: {name, email, password, institution}}
analysis_history = []  # Stores all analyses permanently

print("[*] In-memory user database initialized")
print("[*] Analysis history storage initialized")

# ===================== ML MODEL (Simple Heuristic) =====================
def analyze_url_simple(url):
    """Simple URL phishing detection"""
    score = 0
    reasons = []
    
    # Check for suspicious patterns
    if len(url) > 100:
        score += 20
        reasons.append("Very long URL")
    
    if '@' in url:
        score += 30
        reasons.append("Contains @ symbol (possible credential stuffing)")
    
    if url.count('-') > 4:
        score += 15
        reasons.append("Many dashes in URL")
    
    if not url.startswith('https'):
        score += 10
        reasons.append("No HTTPS encryption")
    
    suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.club']
    if any(url.lower().endswith(tld) for tld in suspicious_tlds):
        score += 20
        reasons.append("Suspicious top-level domain")
    
    # Check for IP address
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        score += 25
        reasons.append("Contains IP address instead of domain")
    
    # Check for login keywords
    login_words = ['login', 'signin', 'verify', 'account', 'secure', 'update']
    if any(word in url.lower() for word in login_words):
        score += 15
        reasons.append("Contains login/verification keywords")
    
    # Calculate risk score (0-100)
    risk_score = min(score, 100)
    
    if risk_score >= 60:
        prediction = "PHISHING"
        level = "High Risk"
        color = "#ef4444"
    elif risk_score >= 30:
        prediction = "SUSPICIOUS"
        level = "Medium Risk"
        color = "#f59e0b"
    else:
        prediction = "SAFE"
        level = "Low Risk"
        color = "#10b981"
    
    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "risk_level": level,
        "risk_color": color,
        "reasons": reasons if reasons else ["No suspicious patterns detected"],
        "confidence": (100 - risk_score) / 100
    }

def analyze_email_simple(text):
    """Simple email/text phishing detection"""
    text_lower = text.lower()
    score = 0
    reasons = []
    
    # Urgency keywords
    urgency_words = ['urgent', 'immediately', '24 hours', 'suspend', 'verify', 'action required', 'final notice', 'suspended']
    for word in urgency_words:
        if word in text_lower:
            score += 15
            reasons.append(f"Contains urgency word: '{word}'")
    
    # Financial keywords
    financial_words = ['bank', 'account', 'password', 'credit', 'ssn', 'social security', 'routing number', 'gift card', 'bitcoin']
    for word in financial_words:
        if word in text_lower:
            score += 12
            reasons.append(f"Contains financial keyword: '{word}'")
    
    # Impersonation
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'bank of america', 'chase']
    for brand in brands:
        if brand in text_lower:
            score += 15
            reasons.append(f"Possible brand impersonation: '{brand}'")
    
    # Links count
    links = len(re.findall(r'http[s]?://|www\.', text))
    if links > 3:
        score += 10
        reasons.append(f"Contains {links} links (possible spam)")
    
    # Generic greeting
    if 'dear customer' in text_lower or 'dear user' in text_lower:
        score += 5
        reasons.append("Uses generic greeting")
    
    risk_score = min(score, 100)
    
    if risk_score >= 60:
        prediction = "PHISHING"
        level = "High Risk"
        color = "#ef4444"
    elif risk_score >= 30:
        prediction = "SUSPICIOUS"
        level = "Medium Risk"
        color = "#f59e0b"
    else:
        prediction = "SAFE"
        level = "Low Risk"
        color = "#10b981"
    
    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "risk_level": level,
        "risk_color": color,
        "reasons": reasons if reasons else ["No suspicious patterns detected"],
        "confidence": (100 - risk_score) / 100
    }

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

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing"""
    data = request.get_json()
    url = data.get('url', '').strip() if data else ''
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400
    
    result = analyze_url_simple(url)
    
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
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        'confidence': result['confidence'],
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id
    })


@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    """Analyze email for phishing"""
    data = request.get_json()
    text = data.get('text', '').strip() or data.get('email', '').strip() or data.get('body', '').strip() if data else ''
    
    if not text:
        return jsonify({'error': 'Email content is required'}), 400
    
    result = analyze_email_simple(text)
    
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
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    analysis_history.append(analysis_record)
    
    return jsonify({
        'success': True,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'risk_color': result['risk_color'],
        'reasons': result['reasons'],
        'confidence': result['confidence'],
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id
    })


@app.route('/api/analyze/message', methods=['POST'])
def analyze_message():
    """Analyze message for phishing"""
    data = request.get_json()
    message = data.get('message', '').strip() if data else ''
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    result = analyze_email_simple(message)
    
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
        'analyzed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    analysis_history.append(analysis_record)
    
    return jsonify({
        'success': True,
        'prediction': result['prediction'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'reasons': result['reasons'],
        'analyzed_at': analysis_record['analyzed_at'],
        'analysis_id': analysis_id
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
        'version': '2.0-simple'
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
            'features': data.get('features', {})
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


# ===================== MAIN =====================
if __name__ == '__main__':
    print("\n" + "="*50)
    print("  PhishGuard AI - Simple Version for Expo")
    print("="*50)
    print("[*] Simple in-memory auth (no database)")
    print("[*] No JWT, no hashing - just works!")
    print(f"[*] Server running on http://localhost:5000")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)