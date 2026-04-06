"""
PhishGuard AI - API Routes
Industry-grade REST API
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Create API Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize JWT
jwt = JWTManager()


# ===================== AUTH ENDPOINTS =====================

@api_bp.route('/auth/register', methods=['POST'])
def register():
    """User registration"""
    data = request.get_json()
    
    # Validate required fields
    required = ['email', 'password']
    for field in required:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'{field} is required'}), 400
    
    # Validate email format
    if '@' not in data['email']:
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    # Validate password strength
    if len(data['password']) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    try:
        from backend.database.db_manager import get_db_manager
        db = get_db_manager()
        
        # Check if user exists
        existing = db.get_user_by_email(data['email'])
        if existing:
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create user
        user_id = db.create_user(
            email=data['email'],
            username=data.get('username', data['email'].split('@')[0]),
            password=data['password'],
            full_name=data.get('full_name', ''),
            institution=data.get('institution', '')
        )
        
        # Create tokens
        access_token = create_access_token(identity=str(user_id))
        refresh_token = create_refresh_token(identity=str(user_id))
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user_id,
                'email': data['email'],
                'username': data.get('username', data['email'].split('@')[0])
            }
        }), 201
        
    except Exception as e:
        logger.error(f"[!] Registration error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500


@api_bp.route('/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    try:
        from backend.database.db_manager import get_db_manager
        db = get_db_manager()
        
        # Verify user
        user = db.verify_user(data['email'], data['password'])
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
        
        # Update last login
        db.update_last_login(user['id'])
        
        # Create tokens
        access_token = create_access_token(identity=str(user['id']))
        refresh_token = create_refresh_token(identity=str(user['id']))
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'username': user['username'],
                'full_name': user.get('full_name', ''),
                'institution': user.get('institution', '')
            }
        })
        
    except Exception as e:
        logger.error(f"[!] Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500


@api_bp.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({'access_token': access_token})


@api_bp.route('/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    try:
        user_id = int(get_jwt_identity())
        from backend.database.db_manager import get_db_manager
        db = get_db_manager()
        
        user = db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user['id'],
            'email': user['email'],
            'username': user['username'],
            'full_name': user.get('full_name', ''),
            'institution': user.get('institution', ''),
            'total_analyses': user.get('total_analyses', 0),
            'threats_found': user.get('threats_found', 0)
        })
    except Exception as e:
        logger.error(f"[!] Get user error: {e}")
        return jsonify({'error': 'Failed to get user'}), 500


# ===================== ANALYSIS ENDPOINTS =====================

@api_bp.route('/analyze/url', methods=['POST'])
@jwt_required()
def analyze_url():
    """Analyze URL for phishing"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400
    
    try:
        from backend.services.ml_service import get_ml_service
        from backend.services.threat_intel import get_threat_intel
        from backend.services.risk_engine import get_risk_engine
        from backend.services.explainer import get_explainer
        from backend.services.sandbox import get_sandbox
        
        ml_service = get_ml_service()
        threat_intel = get_threat_intel()
        risk_engine = get_risk_engine()
        explainer = get_explainer()
        sandbox = get_sandbox()
        
        # 1. ML Prediction
        prediction, confidence = ml_service.predict_url(url)
        
        # 2. Get features
        features = ml_service.extract_url_features(url)[0].tolist()
        feature_dict = {
            'url_length': features[0],
            'has_https': bool(features[1]),
            'has_at_symbol': bool(features[2]),
            'has_ip_address': bool(features[3]),
            'dash_count': features[4],
            'digit_ratio': features[5],
            'special_char_count': features[6],
            'subdomain_count': features[7],
            'suspicious_tld': bool(features[8]),
            'entropy': features[9]
        }
        
        # 3. Threat Intelligence (optional - requires API keys)
        threat_report = threat_intel.get_full_threat_report(url)
        
        # 4. Sandbox Simulation
        sandbox_result = sandbox.simulate_url(url)
        
        # 5. Risk Scoring
        risk_result = risk_engine.calculate_risk_score(
            ml_prediction=prediction,
            ml_confidence=confidence,
            threat_intel=threat_report,
            domain_info=threat_report.get('domain_reputation', {}),
            url_indicators=threat_report.get('url_indicators', {})
        )
        
        # 6. Explainable AI
        explanation = explainer.explain_url(url, prediction, feature_dict)
        
        # 7. Save to database
        user_id = int(get_jwt_identity())
        from backend.database.db_manager import get_db_manager
        db = get_db_manager()
        analysis_id = db.save_analysis(
            user_id=user_id,
            analysis_type='URL',
            content=url,
            prediction=risk_result['risk_level'],
            confidence=risk_result['risk_score'] / 100,
            reasons=explanation.get('risk_indicators', []),
            features=feature_dict,
            risk_score=risk_result['risk_score'],
            threat_intel_data=threat_report if threat_report.get('virustotal', {}).get('available') else None
        )
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'prediction': risk_result['risk_level'],
            'confidence': confidence,
            'risk_score': risk_result['risk_score'],
            'risk_breakdown': risk_result['breakdown'],
            'features': feature_dict,
            'explanation': explanation,
            'threat_intel': threat_report,
            'sandbox': sandbox_result.get('predicted_behavior', []),
            'recommendation': risk_result.get('recommendation', [])[0] if risk_result.get('recommendation') else '',
            'analyzed_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"[!] URL analysis error: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@api_bp.route('/analyze/email', methods=['POST'])
@jwt_required()
def analyze_email():
    """Analyze email content for phishing"""
    data = request.get_json()
    
    text = data.get('text', '') or data.get('body', '')
    subject = data.get('subject', '')
    
    if not text:
        return jsonify({'error': 'Email content is required'}), 400
    
    if len(text) > 10000:
        return jsonify({'error': 'Email too long'}), 400
    
    try:
        from backend.services.ml_service import get_ml_service
        from backend.services.risk_engine import get_risk_engine
        from backend.services.explainer import get_explainer
        
        ml_service = get_ml_service()
        risk_engine = get_risk_engine()
        explainer = get_explainer()
        
        # Combine subject and body
        combined = f"{subject} {text}".lower()
        
        # ML Prediction
        prediction, confidence = ml_service.predict_email(combined)
        
        # Extract features
        features = ml_service._simple_text_features(combined)[0].tolist()
        feature_dict = {
            'urgency_phrases': features[0],
            'financial_keywords': features[1],
            'link_count': features[2],
            'suspicious_brands': features[3],
            'text_length': features[4]
        }
        
        # Risk Scoring
        risk_result = risk_engine.calculate_risk_score(
            ml_prediction=prediction,
            ml_confidence=confidence,
            reasons=explanation.get('risk_indicators', [])
        )
        
        # Explanation
        explanation = explainer.explain_email(combined, prediction, feature_dict)
        
        # Save to database
        user_id = int(get_jwt_identity())
        from backend.database.db_manager import get_db_manager
        db = get_db_manager()
        analysis_id = db.save_analysis(
            user_id=user_id,
            analysis_type='EMAIL',
            content=text[:500],
            prediction=risk_result['risk_level'],
            confidence=risk_result['risk_score'] / 100,
            reasons=explanation.get('risk_indicators', []),
            features=feature_dict
        )
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'prediction': risk_result['risk_level'],
            'risk_score': risk_result['risk_score'],
            'features': feature_dict,
            'explanation': explanation,
            'recommendation': risk_result.get('recommendation', [])[0] if risk_result.get('recommendation') else '',
            'analyzed_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"[!] Email analysis error: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


# ===================== USER DATA ENDPOINTS =====================

@api_bp.route('/user/analyses', methods=['GET'])
@jwt_required()
def get_user_analyses():
    """Get user's analysis history"""
    user_id = int(get_jwt_identity())
    limit = min(int(request.args.get('limit', 50)), 100)
    
    from backend.database.db_manager import get_db_manager
    db = get_db_manager()
    analyses = db.get_user_analyses(user_id, limit)
    
    return jsonify(analyses)


@api_bp.route('/user/analyses/<int:analysis_id>', methods=['GET'])
@jwt_required()
def get_single_analysis(analysis_id):
    """Get single analysis details"""
    user_id = int(get_jwt_identity())
    
    from backend.database.db_manager import get_db_manager
    db = get_db_manager()
    analysis = db.get_analysis_by_id(analysis_id)
    
    if not analysis:
        return jsonify({'error': 'Analysis not found'}), 404
    
    if analysis.get('user_id') != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify(analysis)


@api_bp.route('/user/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """Get user statistics"""
    user_id = int(get_jwt_identity())
    
    from backend.database.db_manager import get_db_manager
    db = get_db_manager()
    stats = db.get_user_stats(user_id)
    
    return jsonify(stats)


# ===================== EXPORT ENDPOINTS =====================

@api_bp.route('/export/pdf', methods=['POST'])
@jwt_required()
def export_pdf():
    """Export analysis as PDF"""
    data = request.get_json()
    analysis_id = data.get('analysis_id')
    
    if not analysis_id:
        return jsonify({'error': 'Analysis ID required'}), 400
    
    user_id = int(get_jwt_identity())
    
    from backend.database.db_manager import get_db_manager
    db = get_db_manager()
    analysis = db.get_analysis_by_id(analysis_id)
    
    if not analysis or analysis.get('user_id') != user_id:
        return jsonify({'error': 'Analysis not found'}), 404
    
    # Generate PDF
    try:
        from backend.utils.pdf_generator import generate_analysis_pdf
        pdf_data = generate_analysis_pdf(analysis)
        
        return pdf_data, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.pdf'
        }
    except Exception as e:
        logger.error(f"[!] PDF generation error: {e}")
        return jsonify({'error': 'PDF generation failed'}), 500


# ===================== HEALTH CHECK =====================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    from backend.services.ml_service import get_ml_service
    
    ml_service = get_ml_service()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'ml_models_loaded': ml_service.is_ready(),
        'version': '2.0.0'
    })


def register_routes(app):
    """Register all routes with Flask app"""
    app.register_blueprint(api_bp)
    jwt.init_app(app)