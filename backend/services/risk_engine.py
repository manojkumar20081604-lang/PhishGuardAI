"""
PhishGuard AI - Risk Scoring Engine
Combines ML predictions + API data + heuristics into unified score (0-100)
"""

import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Risk Scoring Engine (0-100)
    
    Score breakdown:
    - 0-30: Low Risk (SAFE)
    - 31-60: Medium Risk (SUSPICIOUS)
    - 61-100: High Risk (PHISHING)
    """
    
    def __init__(self):
        # Weights for different components
        self.weights = {
            'ml_prediction': 0.35,      # 35% - ML model confidence
            'threat_intel': 0.30,       # 30% - VirusTotal, PhishTank
            'heuristics': 0.20,         # 20% - Rule-based checks
            'domain_reputation': 0.15   # 15% - WHOIS, age, etc.
        }
    
    def calculate_risk_score(
        self,
        ml_prediction: str,
        ml_confidence: float,
        threat_intel: Dict = None,
        domain_info: Dict = None,
        url_indicators: Dict = None,
        reasons: List[str] = None
    ) -> Dict:
        """
        Calculate overall risk score (0-100)
        
        Args:
            ml_prediction: 'safe', 'suspicious', or 'phishing'
            ml_confidence: 0.0 to 1.0
            threat_intel: Threat intelligence results
            domain_info: Domain WHOIS info
            url_indicators: URL pattern analysis
            reasons: List of detection reasons
        
        Returns:
            Dictionary with risk_score, risk_level, and breakdown
        """
        
        # 1. ML Score (0-100)
        ml_score = self._calculate_ml_score(ml_prediction, ml_confidence)
        
        # 2. Threat Intelligence Score (0-100)
        ti_score = self._calculate_threat_intel_score(threat_intel or {})
        
        # 3. Heuristics Score (0-100)
        heuristic_score = self._calculate_heuristic_score(reasons or [])
        
        # 4. Domain Reputation Score (0-100)
        domain_score = self._calculate_domain_score(domain_info or {}, url_indicators or {})
        
        # Calculate weighted total
        risk_score = int(
            ml_score * self.weights['ml_prediction'] +
            ti_score * self.weights['threat_intel'] +
            heuristic_score * self.weights['heuristics'] +
            domain_score * self.weights['domain_reputation']
        )
        
        # Determine risk level
        if risk_score >= 61:
            risk_level = 'PHISHING'
            risk_color = '#ef4444'
        elif risk_score >= 31:
            risk_level = 'SUSPICIOUS'
            risk_color = '#f59e0b'
        else:
            risk_level = 'SAFE'
            risk_color = '#10b981'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'breakdown': {
                'ml_score': ml_score,
                'threat_intel_score': ti_score,
                'heuristic_score': heuristic_score,
                'domain_score': domain_score
            },
            'weights_used': self.weights,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _calculate_ml_score(self, prediction: str, confidence: float) -> int:
        """Calculate ML component score"""
        if prediction == 'phishing':
            return int(min(confidence * 100 + 20, 100))
        elif prediction == 'suspicious':
            return int(confidence * 60 + 20)
        else:  # safe
            return int((1 - confidence) * 30)
    
    def _calculate_threat_intel_score(self, ti_data: Dict) -> int:
        """Calculate threat intelligence component score"""
        score = 0
        
        # VirusTotal contribution
        if ti_data.get('virustotal', {}).get('available'):
            vt = ti_data['virustotal']
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            
            # Each malicious detection adds 8 points (max 40)
            score += min(malicious * 8, 40)
            # Each suspicious detection adds 5 points (max 20)
            score += min(suspicious * 5, 20)
        
        # PhishTank contribution
        if ti_data.get('phishtank', {}).get('available'):
            pt = ti_data['phishtank']
            if pt.get('in_database'):
                score += 30
            if pt.get('verified') == 'true':
                score += 10
        
        return min(score, 100)
    
    def _calculate_heuristic_score(self, reasons: List[str]) -> int:
        """Calculate heuristic component score"""
        score = 0
        
        high_risk_reasons = [
            'contains @ symbol',
            'uses IP address',
            'very long URL',
            'login page',
            'credential harvesting',
            'fake login'
        ]
        
        medium_risk_reasons = [
            'no HTTPS',
            'suspicious TLD',
            'unusual domain',
            'multiple redirects'
        ]
        
        for reason in reasons:
            reason_lower = reason.lower()
            
            # High risk reasons: +15 each
            for hr in high_risk_reasons:
                if hr in reason_lower:
                    score += 15
                    break
            
            # Medium risk reasons: +8 each
            else:
                for mr in medium_risk_reasons:
                    if mr in reason_lower:
                        score += 8
                        break
        
        return min(score, 100)
    
    def _calculate_domain_score(self, domain_info: Dict, url_indicators: Dict) -> int:
        """Calculate domain reputation component score"""
        score = 0
        
        # Domain age (new domains are suspicious)
        age_days = domain_info.get('age_days')
        if age_days is not None:
            if age_days < 7:
                score += 30  # Less than a week - very suspicious
            elif age_days < 30:
                score += 15  # Less than a month - somewhat suspicious
            elif age_days > 365:
                score -= 10  # Over a year - less suspicious
        
        # Suspicious indicators
        risk_factors = domain_info.get('risk_factors', [])
        score += len(risk_factors) * 8
        
        # URL indicators
        url_risk = url_indicators.get('risk_score', 0)
        score += min(url_risk, 20)
        
        # Brand mentions (typosquatting)
        brand_mentions = url_indicators.get('brand_mentions', [])
        score += len(brand_mentions) * 10
        
        return max(0, min(score, 100))
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get security recommendation based on risk level"""
        recommendations = {
            'PHISHING': [
                'DO NOT visit this URL',
                'DO NOT enter any personal information',
                'Report to your IT security team',
                'Forward to phishing@company.com if from work',
                'Delete any emails containing this link'
            ],
            'SUSPICIOUS': [
                'Exercise caution before visiting',
                'Verify the sender through official channels',
                'Do not enter passwords or financial information',
                'Check the actual URL by hovering over links',
                'When in doubt, navigate directly to the website'
            ],
            'SAFE': [
                'This appears to be a legitimate URL',
                'Always verify before entering sensitive data',
                'Keep your browser and security software updated'
            ]
        }
        return recommendations.get(risk_level, ['Unknown risk level'])
    
    def get_score_explanation(self, score_data: Dict) -> str:
        """Get human-readable explanation of the score"""
        breakdown = score_data.get('breakdown', {})
        
        explanation = f"""
Risk Score: {score_data['risk_score']}/100 ({score_data['risk_level']})

Score Breakdown:
• ML Model: {breakdown.get('ml_score', 0)}/100 ({self.weights['ml_prediction']*100:.0f}% weight)
• Threat Intelligence: {breakdown.get('threat_intel_score', 0)}/100 ({self.weights['threat_intel']*100:.0f}% weight)
• Heuristic Analysis: {breakdown.get('heuristic_score', 0)}/100 ({self.weights['heuristics']*100:.0f}% weight)
• Domain Reputation: {breakdown.get('domain_score', 0)}/100 ({self.weights['domain_reputation']*100:.0f}% weight)

Recommendation: {score_data.get('recommendation', ['N/A'])[0] if score_data.get('recommendation') else 'N/A'}
        """
        return explanation.strip()


# Global instance
risk_engine = None


def get_risk_engine() -> RiskScoringEngine:
    """Get risk scoring engine instance"""
    global risk_engine
    if risk_engine is None:
        risk_engine = RiskScoringEngine()
    return risk_engine