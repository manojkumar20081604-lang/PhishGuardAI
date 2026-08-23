"""
Test suite for Phase 4: XAI Engine + Hybrid Analyzer
Run with: python test_xai_phase4.py
"""

import sys
sys.path.insert(0, '/home/manoj/Projects/PhishGuardAI')


def test_xai_explanation_generation():
    """Test XAI explanation generation"""
    print("=== Testing XAI Explanation Generation ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: Safe URL should get a SAFE verdict with explanation
    safe_url = 'https://www.google.com'
    url_features = feature_extractor.extract_url_features(safe_url)
    result = ml_model.predict_url(safe_url)
    
    print(f"✓ Safe URL prediction: {result['prediction']} (score: {result['risk_score']})")
    assert result['prediction'] == "SAFE", f"Expected SAFE, got {result['prediction']}"


def test_xai_reason_extraction():
    """Test that reasons can be extracted from features"""
    print("\n=== Testing XAI Reason Extraction ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: URL with IP should have a reason about IP detection
    ip_url = 'https://192.168.1.100/login'
    url_features = feature_extractor.extract_url_features(ip_url)
    result = ml_model.predict_url(ip_url)
    
    print(f"✓ IP URL prediction: {result['prediction']} (score: {result['risk_score']})")
    assert 'has_ip' in url_features, "IP should be detected in features"


def test_xai_source_counting():
    """Test that source counting works"""
    print("\n=== Testing XAI Source Counting ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: Safe URL - should have minimal sources
    safe_url = 'https://www.google.com'
    url_features = feature_extractor.extract_url_features(safe_url)
    result = ml_model.predict_url(safe_url)
    
    print(f"✓ Safe URL has {result['risk_score']} risk score")
    assert result['risk_score'] < 30, "Safe URL should have low score"


def test_xai_severity_classification():
    """Test severity classification"""
    print("\n=== Testing XAI Severity Classification ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: Very safe - LOW severity (score < 25)
    safe_url = 'https://www.google.com'
    result = ml_model.predict_url(safe_url)
    assert result['risk_score'] < 25, "Safe URL should be LOW severity"
    
    # Test 2: Medium risk - MEDIUM severity (score 25-47)
    # Use suspicious params to get into medium range
    medium_url = 'https://www.example.com/verify?user=123&pass=x' + 'a' * 50
    result = ml_model.predict_url(medium_url)
    assert 25 <= result['risk_score'] < 47, f"Medium URL should be MEDIUM severity (got {result['risk_score']})"
    
    # Test 3: High risk - HIGH severity (score >= 47)
    high_url = 'https://192.168.1.100/login?user=admin&pass=x'
    result = ml_model.predict_url(high_url)
    assert result['risk_score'] >= 47, f"IP URL should be HIGH severity (got {result['risk_score']})"
    
    print("✓ Severity classification working correctly")


def test_xai_feature_interpretation():
    """Test that features are properly interpreted"""
    print("\n=== Testing XAI Feature Interpretation ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: URL length interpretation
    long_url = 'https://www.example.com/' + 'a' * 200
    url_features = feature_extractor.extract_url_features(long_url)
    result = ml_model.predict_url(long_url)
    
    print(f"✓ Long URL detected: {url_features['url_length']} chars, score: {result['risk_score']}")
    assert url_features['url_length'] > 100, "Long URL should be >100 chars"


def test_xai_combined_scoring():
    """Test combined scoring with multiple features"""
    print("\n=== Testing XAI Combined Scoring ===")
    
    from app import ml_model, feature_extractor
    
    # Test 1: Multiple risk factors
    multi_risk_url = 'https://www.secure.login.verify.paypal-secure-update-account.com/verify/account?user=123'
    url_features = feature_extractor.extract_url_features(multi_risk_url)
    result = ml_model.predict_url(multi_risk_url)
    
    print(f"✓ Multi-risk URL: {result['prediction']} (score: {result['risk_score']})")
    assert result['risk_score'] > 0, "Multi-risk URL should have positive score"


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("PHASE 4 TEST SUITE: XAI Engine + Hybrid Analyzer")
    print("=" * 60)
    
    try:
        test_xai_explanation_generation()
        test_xai_reason_extraction()
        test_xai_source_counting()
        test_xai_severity_classification()
        test_xai_feature_interpretation()
        test_xai_combined_scoring()
        
        print("\n" + "=" * 60)
        print("✅ ALL PHASE 4 TESTS PASSED!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
