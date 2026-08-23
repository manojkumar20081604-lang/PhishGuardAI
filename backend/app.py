"""
PhishGuardAI Backend - Flask API Server
========================================
Main application entry point with routing, middleware, and service orchestration.
"""

import os
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
from datetime import datetime
from functools import wraps
from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session
from models import User, ScanHistory, SystemConfig, ScanType, RiskLevel
from database import get_db, engine, SessionLocal, ScopedSession
from services.threat_intel_cache import get_cache_service
from services.model_versioning import get_version_service
from services.scan_history import get_history_service
from services.dashboard_metrics import get_metrics_service
from services.ml_service import get_ml_service
from services.risk_engine import get_risk_engine
from services.explainer import get_explainer


# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'phishguard-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max request size


# Database session factory
def get_session():
    """Get database session for current request."""
    return ScopedSession()

@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up database sessions after requests."""
    if exception is not None:
        try:
            ScopedSession().rollback()
        except Exception:
            pass
    ScopedSession.remove()


# Middleware
@app.before_request
def before_request():
    """Run before each request."""
    g.start_time = datetime.utcnow()

@app.after_request
def after_request(response):
    """Add headers and logging to all responses."""
    response.headers['X-PhishGuard-Version'] = '1.0.0'
    response.headers['X-Request-ID'] = getattr(g, 'request_id', None)
    
    # Log request duration
    if hasattr(g, 'start_time'):
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        response.headers['X-Response-Time'] = f'{duration:.3f}s'
    
    return response


# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'path': request.path}), 404

@app.errorhandler(500)
def internal_error(error):
    db = get_session()
    error_msg = f'Internal server error: {str(error)}'
    if hasattr(error, 'message'):
        error_msg = str(error.message)
    return jsonify({'error': error_msg}), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': 60}), 429


# API Routes - Core Analysis
@app.route('/api/v1/analyze/url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing (ML + risk engine + XAI). Main extension endpoint."""
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400

    db = get_session()
    try:
        ml_service = get_ml_service()
        risk_engine = get_risk_engine()
        explainer = get_explainer()

        # 1. ML prediction ('safe' | 'suspicious' | 'phishing')
        prediction, confidence = ml_service.predict_url(url)

        # 2. Risk scoring
        risk_result = risk_engine.calculate_risk_score(
            ml_prediction=prediction,
            ml_confidence=confidence
        )

        # 3. Explainable AI
        explanation = explainer.explain_url(url, prediction)

        # 4. Persist scan (extension scans run under a shared system user)
        system_user = db.query(User).filter(User.email == 'extension@phishguard.local').first()
        if not system_user:
            system_user = User(
                username='extension',
                email='extension@phishguard.local',
                hashed_password=''
            )
            db.add(system_user)
            db.commit()
            db.refresh(system_user)

        history_service = get_history_service(db)
        recommendation = risk_result.get('recommendation', [])
        scan = history_service.save_scan_result(
            user_id=system_user.id,
            session_id=None,
            scan_type=ScanType.URL,
            input_url=url,
            risk_score=float(risk_result['risk_score']),
            risk_level=_map_risk_level(risk_result['risk_score']),
            features_json=explanation.get('features', {}),
            explanation_text=explanation.get('summary', ''),
            feature_importance_json={}
        )

        return jsonify({
            'success': True,
            'session_id': scan.session_id,
            'analysis_id': scan.id,
            'url': url,
            'prediction': prediction,
            'confidence': confidence,
            'risk_score': round(float(risk_result['risk_score']), 2),
            'risk_level': risk_result['risk_level'],
            'risk_breakdown': risk_result.get('breakdown', {}),
            'reasons': explanation.get('risk_indicators', []),
            'summary': explanation.get('summary', ''),
            'security_tips': explanation.get('security_tips', []),
            'recommendation': recommendation[0] if recommendation else '',
            'analyzed_at': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        db.rollback()
        print(f"[!] URL analysis error: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


def _map_risk_level(score: float):
    """Map a 0-100 risk score to the RiskLevel enum."""
    if score >= 85:
        return RiskLevel.CRITICAL
    if score >= 65:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# API Routes - Threat Intel Cache
@app.route('/api/v1/threat-intel/<source_type>/<identifier>', methods=['GET'])
def get_threat_intel(source_type, identifier):
    """Get cached threat intel for a URL/email."""
    db = get_session()
    cache_service = get_cache_service(db)
    
    # Determine scan type from source
    scan_type_map = {
        'virustotal': ScanType.URL,
        'phishtank': ScanType.EMAIL,
        'safebrowsing': ScanType.TEXT,
        'urlvoid': ScanType.URL
    }
    
    scan_type = scan_type_map.get(source_type, ScanType.URL)
    result = cache_service.get_cached(source_type, identifier, scan_type)
    
    if result:
        return jsonify(result), 200
    
    # Cache miss - fetch fresh data (placeholder for now)
    result = {source_type: {'status': 'fetching', 'identifier': identifier}}
    cache_service.set_cache(source_type, identifier, scan_type, result)
    
    return jsonify(result), 200


# API Routes - Model Versioning
@app.route('/api/v1/models/<model_type>/versions', methods=['GET'])
def list_model_versions(model_type):
    """List all versions of a model."""
    db = get_session()
    version_service = get_version_service(db)
    
    try:
        versions = version_service.get_all_versions(model_type)
        return jsonify({
            'model_type': model_type,
            'versions': [
                {
                    'version_name': v.version_name,
                    'accuracy': round(v.accuracy, 4) if v.accuracy else None,
                    'precision': round(v.precision, 4) if v.precision else None,
                    'recall': round(v.recall, 4) if v.recall else None,
                    'f1_score': round(v.f1_score, 4) if v.f1_score else None,
                    'is_active': v.is_active,
                    'deployment_date': v.deployment_date.isoformat() if v.deployment_date else None
                }
                for v in versions
            ]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/models/<model_type>/versions/<version_name>', methods=['GET'])
def get_model_version(model_type, version_name):
    """Get details of a specific model version."""
    db = get_session()
    version_service = get_version_service(db)
    
    try:
        versions = version_service.get_all_versions(model_type)
        version = next((v for v in versions if v.version_name == version_name), None)
        
        if not version:
            return jsonify({'error': 'Version not found'}), 404
        
        return jsonify({
            'version_name': version.version_name,
            'model_type': version.model_type,
            'accuracy': round(version.accuracy, 4) if version.accuracy else None,
            'precision': round(version.precision, 4) if version.precision else None,
            'recall': round(version.recall, 4) if version.recall else None,
            'f1_score': round(version.f1_score, 4) if version.f1_score else None,
            'xai_enabled': version.xai_enabled,
            'replaced_version': version.replaced_version,
            'is_active': version.is_active,
            'deployment_date': version.deployment_date.isoformat() if version.deployment_date else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/models/<model_type>/versions/<version_name>/activate', methods=['POST'])
def activate_model_version(model_type, version_name):
    """Activate a specific model version."""
    db = get_session()
    version_service = get_version_service(db)
    
    try:
        version_service.activate_version(version_name)
        return jsonify({'message': f'Activated {version_name}'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes - Scan History
@app.route('/api/v1/scans/<session_id>', methods=['GET'])
def get_scan_by_session(session_id):
    """Get scan result by session ID (for browser extension callbacks)."""
    db = get_session()
    history_service = get_history_service(db)
    
    try:
        scan = history_service.get_scan_by_session(session_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Convert to JSON-serializable format
        result = {
            'session_id': scan.session_id,
            'scan_type': scan.scan_type.name if hasattr(scan.scan_type, 'name') else str(scan.scan_type),
            'risk_score': round(scan.risk_score, 4) if isinstance(scan.risk_score, float) else scan.risk_score,
            'risk_level': scan.risk_level.name if hasattr(scan.risk_level, 'name') else str(scan.risk_level),
            'input_url': scan.input_url,
            'input_email': scan.input_email,
            'input_text': scan.input_text,
            'features_json': json.loads(scan.features_json) if scan.features_json and isinstance(scan.features_json, str) else (scan.features_json or {}),
            'model_version': scan.model_version,
            'explanation_text': scan.explanation_text,
            'feature_importance_json': json.loads(scan.feature_importance_json) if scan.feature_importance_json and isinstance(scan.feature_importance_json, str) else (scan.feature_importance_json or {}),
            'sandbox_results_json': json.loads(scan.sandbox_results_json) if scan.sandbox_results_json and isinstance(scan.sandbox_results_json, str) else (scan.sandbox_results_json or {}),
            'user_feedback': scan.user_feedback,
            'feedback_text': scan.feedback_text,
            'is_false_positive': scan.is_false_positive,
            'created_at': scan.created_at.isoformat() if scan.created_at else None
        }
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/scans/user/<int:user_id>', methods=['GET'])
def get_user_scans(user_id):
    """Get scans for a specific user with pagination."""
    db = get_session()
    history_service = get_history_service(db)
    
    try:
        # Get query params
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        scan_type_str = request.args.get('scan_type')
        
        scan_type = ScanType[scan_type_str] if scan_type_str else None
        
        scans = history_service.get_user_scans(user_id, limit=limit, offset=offset, scan_type=scan_type)
        
        # Convert to JSON-serializable format
        result = {
            'user_id': user_id,
            'total': len(scans),
            'scans': [
                {
                    'session_id': s.session_id,
                    'scan_type': s.scan_type.name if hasattr(s.scan_type, 'name') else str(s.scan_type),
                    'risk_score': round(s.risk_score, 4) if isinstance(s.risk_score, float) else s.risk_score,
                    'risk_level': s.risk_level.name if hasattr(s.risk_level, 'name') else str(s.risk_level),
                    'input_url': s.input_url,
                    'input_email': s.input_email,
                    'created_at': s.created_at.isoformat() if s.created_at else None
                }
                for s in scans
            ]
        }
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes - Dashboard Metrics
@app.route('/api/v1/metrics/overview', methods=['GET'])
def get_overview_metrics():
    """Get high-level overview metrics for main dashboard."""
    db = get_session()
    metrics_service = get_metrics_service(db)
    
    try:
        days = request.args.get('days', 7, type=int)
        metrics = metrics_service.get_overview_metrics(days=days)
        
        return jsonify(metrics), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/metrics/user/<int:user_id>', methods=['GET'])
def get_user_metrics(user_id):
    """Get metrics for a specific user."""
    db = get_session()
    metrics_service = get_metrics_service(db)
    
    try:
        metrics = metrics_service.get_user_metrics(user_id)
        
        return jsonify(metrics), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/metrics/system/health', methods=['GET'])
def get_system_health():
    """Get system health metrics."""
    db = get_session()
    metrics_service = get_metrics_service(db)
    
    try:
        health = metrics_service.get_system_health()
        
        return jsonify(health), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/metrics/trends/risk', methods=['GET'])
def get_risk_trends():
    """Get risk score trends over time."""
    db = get_session()
    metrics_service = get_metrics_service(db)
    
    try:
        user_id = request.args.get('user_id')
        days = request.args.get('days', 7, type=int)
        
        if user_id:
            trends = metrics_service.get_risk_trends(user_id=int(user_id), days=days)
        else:
            trends = metrics_service.get_risk_trends(days=days)
        
        return jsonify({'trends': trends}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes - User Management (Simplified for now)
@app.route('/api/v1/users', methods=['POST'])
def create_user():
    """Create a new user."""
    db = get_session()
    
    try:
        data = request.get_json()
        
        # Check if username already exists
        existing = User.query.filter_by(username=data['username']).first()
        if existing:
            return jsonify({'error': 'Username already exists'}), 400
        
        user = User(
            username=data['username'],
            email=data.get('email'),
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(user)
        db.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user_id': user.id,
            'username': user.username
        }), 201
    
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get user details."""
    db = get_session()
    
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes - System Configuration
@app.route('/api/v1/config', methods=['GET'])
def get_config():
    """Get system configuration."""
    db = get_session()
    
    try:
        config = SystemConfig.query.first()
        
        if not config:
            return jsonify({
                'version': '1.0.0',
                'name': 'PhishGuardAI',
                'description': 'Advanced Phishing Detection with Explainable AI'
            }), 200
        
        return jsonify({
            'version': '1.0.0',
            'name': config.name,
            'description': config.description,
            'features': [f.feature_name for f in config.features] if hasattr(config, 'features') else [],
            'updated_at': config.updated_at.isoformat() if config.updated_at else None
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API Routes - Feedback (for user feedback on scans)
@app.route('/api/v1/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback on a scan result."""
    db = get_session()
    
    try:
        data = request.get_json()
        
        # TODO: Create FeedbackEntry record and link to ScanHistory
        
        return jsonify({
            'message': 'Feedback submitted successfully',
            'session_id': data.get('session_id'),
            'feedback_type': data.get('type')
        }), 201
    
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


# Health Check Endpoint
@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers and monitoring."""
    try:
        # Test database connection
        db = get_session()
        result = db.execute(sql_text("SELECT 1")).fetchone()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected' if result else 'disconnected',
            'version': '1.0.0',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


# Static Files (for browser extension communication)
@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files for browser extension."""
    return send_from_directory('static', path)


if __name__ == '__main__':
    print("=" * 60)
    print("PhishGuardAI Backend Server")
    print("=" * 60)
    
    # Initialize database tables
    from database import init_database
    init_database()
    
    # Start server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
    
    print(f"🚀 Starting server on http://localhost:{port}")
    print(f"   Debug mode: {debug}")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
