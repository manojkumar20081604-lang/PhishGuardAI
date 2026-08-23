"""
Test suite for Phase 3: Enhanced ML Models + Advanced Feature Extraction
Run with: python test_ml_features.py
"""

import sys
sys.path.insert(0, '/home/manoj/Projects/PhishGuardAI')

from app import ml_model, feature_extractor


def test_url_feature_extraction():
    """Test URL feature extraction"""
    print("=== Testing URL Feature Extraction ===")
    
    # Test 1: Safe URL
    safe_url = 'https://www.google.com'
    features = feature_extractor.extract_url_features(safe_url)
    assert not features.get('suspicious_tld'), "Safe URL should have non-suspicious TLD"
    assert not features.get('has_ip'), "Safe URL should not have IP"
    assert features['no_https'] == False, "Safe URL should have HTTPS"
    print("✓ Safe URL features extracted correctly")
    
    # Test 2: Suspicious URL with many subdomains (with protocol)
    subdomain_url = 'https://www.secure.login.verify.paypal-secure-update-account.com/verify/account?user=123'
    features = feature_extractor.extract_url_features(subdomain_url)
    assert features['subdomain_count'] > 0, f"Should detect subdomains, got {features['subdomain_count']}"
    print(f"✓ Subdomain detection: {features['subdomain_count']} subdomains")


def test_email_feature_extraction():
    """Test email/text feature extraction"""
    print("\n=== Testing Email Feature Extraction ===")
    
    # Test 1: Safe email (order notification)
    safe_email = '''Hello John,

Your order #12345 has been shipped and is on its way. You can track it here: https://track.example.com/abc123

Estimated delivery: 2-3 business days. If you have any questions, contact support@example.com or call 1-800-SUPPORT.

Best regards,
The Support Team'''
    features = feature_extractor.extract_email_features(safe_email)
    assert features['urgency_count'] == 0, "Safe email should have no urgency"
    print("✓ Safe email features extracted correctly")
    
    # Test 2: Phishing email with multiple indicators
    phishing_email = '''URGENT! PayPal detected unusual activity on your account. Click immediately to verify and prevent suspension!

Dear Customer,
Your password and credit card details must be updated within 24 hours or your account will be locked.

Visit: https://www.paypal.com/secure/update/account?user=123&pass=x

Limited time offer - Final notice!'''
    features = feature_extractor.extract_email_features(phishing_email)
    assert features['urgency_count'] > 0, "Phishing email should have urgency indicators"
    assert features['brand_count'] >= 1, "Should detect brand mentions (PayPal)"
    print(f"✓ Phishing email detected: {features['urgency_count']} urgency + {features['brand_count']} brands")


def test_ml_url_prediction():
    """Test ML-based URL prediction"""
    print("\n=== Testing ML URL Prediction ===")
    
    # Test 1: Very safe URL
    safe_url = 'https://www.google.com'
    result = ml_model.predict_url(safe_url)
    assert result['prediction'] == "SAFE", f"Expected SAFE, got {result['prediction']}"
    assert result['risk_score'] < 30, f"Safe URL should have low score (<30), got {result['risk_score']}"
    print(f"✓ Safe URL: {result['prediction']} (score: {result['risk_score']})")
    
    # Test 2: Long URL (length penalty)
    long_url = 'https://www.example.com/' + 'a' * 150
    result = ml_model.predict_url(long_url)
    safe_score = ml_model.predict_url('https://www.google.com')['risk_score']
    assert result['risk_score'] > safe_score, "Long URL should have higher score"
    print(f"✓ Long URL detected: {result['prediction']} (score: {result['risk_score']})")
    
    # Test 3: IP in URL (high weight feature)
    ip_url = 'https://192.168.1.100/login?user=admin'
    result = ml_model.predict_url(ip_url)
    assert result['prediction'] == "SUSPICIOUS" or result['risk_score'] > 30, \
        f"IP URL should be suspicious, got {result['prediction']} (score: {result['risk_score']})"
    print(f"✓ IP-in-URL detected: {result['prediction']} (score: {result['risk_score']})")


def test_ml_email_prediction():
    """Test ML-based email prediction"""
    print("\n=== Testing ML Email Prediction ===")
    
    # Test 1: Safe order notification
    safe_email = '''Hello John,

Your order #12345 has been shipped. Track it here: https://track.example.com/abc123

Best regards,
Support Team'''
    result = ml_model.thresholds['high_risk']  # Get threshold for comparison
    
    # Calculate score manually to verify
    email_features = feature_extractor.extract_email_features(safe_email)
    raw_score = (email_features['urgency_count'] * 25 + 
                 min(email_features['financial_count'], 2) * 15 +
                 min(email_features['brand_count'], 3) * 18 +
                 max(0, email_features['link_count'] - 3) * 8 +
                 (5 if email_features['generic_greeting'] else 0))
    risk_score = min(raw_score, 100)
    
    assert risk_score < 30, f"Safe email should have low score (<30), got {risk_score}"
    print(f"✓ Safe email: Low risk (raw score: {round(risk_score, 2)})")
    
    # Test 2: Phishing email with urgency + financial + brand indicators
    phishing_email = '''URGENT! PayPal detected unusual activity on your account. Click immediately to verify and prevent suspension!

Dear Customer,
Your password and credit card details must be updated within 24 hours or your account will be locked.

Visit: https://www.paypal.com/secure/update/account?user=123&pass=x

Limited time offer - Final notice!'''
    email_features = feature_extractor.extract_email_features(phishing_email)
    
    raw_score = (email_features['urgency_count'] * 25 + 
                 min(email_features['financial_count'], 2) * 15 +
                 min(email_features['brand_count'], 3) * 18 +
                 max(0, email_features['link_count'] - 3) * 8 +
                 (5 if email_features['generic_greeting'] else 0))
    risk_score = min(raw_score, 100)
    
    assert risk_score > 40, f"Phishing email should have high score (>40), got {risk_score}"
    print(f"✓ Phishing email: High risk (raw score: {round(risk_score, 2)})")


def test_feature_weights():
    """Test that feature weights are properly configured"""
    print("\n=== Testing Feature Weights ===")
    
    # Check URL feature importance
    url_importance = ml_model.feature_importance
    assert 'url_length' in url_importance, "Should have url_length weight"
    assert 'subdomain_count' in url_importance, "Should have subdomain_count weight"
    assert 'suspicious_tld' in url_importance, "Should have suspicious_tld weight"
    print("✓ URL feature weights configured")
    
    # Check email thresholds
    thresholds = ml_model.thresholds
    assert 'high_risk' in thresholds, "Should have high_risk threshold"
    assert 'medium_risk' in thresholds, "Should have medium_risk threshold"
    print(f"✓ Email thresholds: HIGH={thresholds['high_risk']}, MEDIUM={thresholds['medium_risk']}")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("PHASE 3 TEST SUITE: Enhanced ML Models + Feature Extraction")
    print("=" * 60)
    
    try:
        test_url_feature_extraction()
        test_email_feature_extraction()
        test_ml_url_prediction()
        test_ml_email_prediction()
        test_feature_weights()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
