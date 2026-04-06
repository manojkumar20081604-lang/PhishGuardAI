"""
PhishGuard AI - Simple Flask App for Science Expo
No database - just works!
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from datetime import datetime
import os
import re

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
    """Generate simple PDF report"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        import io
        
        # Create PDF in memory
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Title
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(colors.HexColor("#00d4ff"))
        c.drawString(50, height - 50, "PhishGuard AI - Analysis Report")
        
        # Line
        c.setStrokeColor(colors.HexColor("#00d4ff"))
        c.setLineWidth(2)
        c.line(50, height - 60, width - 50, height - 60)
        
        # Details
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        
        y = height - 100
        
        # Prediction
        prediction = data.get('prediction', 'Unknown')
        risk_score = data.get('risk_score', 0)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, f"Result: {prediction}")
        y -= 25
        
        # Risk Score
        c.setFont("Helvetica", 14)
        c.drawString(50, y, f"Risk Score: {risk_score}/100")
        y -= 30
        
        # URL/Content
        content = data.get('content', data.get('url', ''))
        if content:
            c.setFont("Helvetica", 12)
            c.drawString(50, y, "Analyzed Content:")
            y -= 20
            c.setFont("Helvetica-Oblique", 10)
            if len(content) > 70:
                c.drawString(50, y, content[:70])
                y -= 15
                c.drawString(50, y, content[70:])
            else:
                c.drawString(50, y, content)
            y -= 30
        
        # Reasons
        reasons = data.get('reasons', [])
        if reasons:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "Detection Reasons:")
            y -= 20
            c.setFont("Helvetica", 10)
            for reason in reasons[:5]:
                c.drawString(60, y, f"• {reason}")
                y -= 15
        
        # Date
        y -= 20
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.gray)
        analyzed_at = data.get('analyzed_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        c.drawString(50, y, f"Generated: {analyzed_at}")
        
        # Footer
        c.drawString(50, 30, "PhishGuard AI - Advanced Phishing Detection System")
        
        c.save()
        buffer.seek(0)
        
        return buffer.getvalue(), 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=phishguard_report.pdf'
        }
        
    except ImportError:
        return jsonify({'error': 'PDF generation not available'}), 500
    except Exception as e:
        print(f"[!] PDF error: {e}")
        return jsonify({'error': 'Failed to generate PDF'}), 500


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