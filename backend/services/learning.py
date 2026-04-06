"""
PhishGuard AI - Self-Learning System
Automatically improves based on user feedback and scan data
"""

import os
import json
import logging
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)


class SelfLearningEngine:
    """
    Self-Learning Capability:
    - Stores all scan results
    - Analyzes patterns in detections
    - Retrains model when enough new data
    - Improves detection accuracy over time
    """
    
    def __init__(self, data_dir: str = 'learning_data'):
        self.data_dir = data_dir
        self.feedback_file = os.path.join(data_dir, 'user_feedback.json')
        self.stats_file = os.path.join(data_dir, 'learning_stats.json')
        self.retrain_threshold = 100  # Retrain after 100 new scans
        self.last_retrain = None
        os.makedirs(data_dir, exist_ok=True)
        self._load_stats()
    
    def _load_stats(self):
        """Load learning statistics"""
        if os.path.exists(self.stats_file):
            with open(self.stats_file, 'r') as f:
                stats = json.load(f)
                self.total_scans = stats.get('total_scans', 0)
                self.last_retrain = stats.get('last_retrain')
        else:
            self.total_scans = 0
            self.last_retrain = None
    
    def _save_stats(self):
        """Save learning statistics"""
        stats = {
            'total_scans': self.total_scans,
            'last_retrain': self.last_retrain,
            'updated_at': datetime.now().isoformat()
        }
        with open(self.stats_file, 'w') as f:
            json.dump(stats, f)
    
    def record_scan(self, url: str, prediction: str, risk_score: int, correct: bool = None):
        """Record a scan for learning"""
        self.total_scans += 1
        
        # Save scan for potential training data
        scan_data = {
            'url': url[:200],
            'prediction': prediction,
            'risk_score': risk_score,
            'timestamp': datetime.now().isoformat(),
            'user_verified': correct  # If user confirms/dismisses
        }
        
        # Append to feedback file
        try:
            with open(self.feedback_file, 'a') as f:
                f.write(json.dumps(scan_data) + '\n')
        except Exception as e:
            logger.error(f"[!] Failed to record scan: {e}")
        
        self._save_stats()
        
        # Check if we should retrain
        if self.total_scans >= self.retrain_threshold:
            self.should_retrain = True
            logger.info(f"[*] Self-learning: {self.total_scans} scans recorded, recommend retraining")
    
    def record_feedback(self, scan_id: str, correct: bool, user_correction: str = None):
        """Record user feedback on a scan"""
        feedback = {
            'scan_id': scan_id,
            'correct': correct,
            'user_correction': user_correction,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(self.feedback_file, 'a') as f:
                f.write(json.dumps(feedback) + '\n')
            logger.info(f"[*] Self-learning: Recorded user feedback for scan {scan_id}")
        except Exception as e:
            logger.error(f"[!] Failed to record feedback: {e}")
    
    def analyze_patterns(self) -> dict:
        """Analyze patterns in scan data to improve detection"""
        if not os.path.exists(self.feedback_file):
            return {'patterns': [], 'insights': []}
        
        try:
            scans = []
            with open(self.feedback_file, 'r') as f:
                for line in f:
                    try:
                        scans.append(json.loads(line))
                    except:
                        continue
            
            # Analyze patterns
            predictions = [s['prediction'] for s in scans]
            prediction_counts = Counter(predictions)
            
            # Find common patterns in high-risk scans
            phishing_scans = [s for s in scans if s.get('prediction') in ['PHISHING', 'phishing']]
            
            insights = [
                f"Total scans recorded: {len(scans)}",
                f"Phishing detected: {prediction_counts.get('PHISHING', 0) + prediction_counts.get('phishing', 0)}",
                f"Suspicious: {prediction_counts.get('SUSPICIOUS', 0)}",
                f"Safe: {prediction_counts.get('SAFE', 0) + prediction_counts.get('safe', 0)}"
            ]
            
            return {
                'total_scans': len(scans),
                'prediction_distribution': dict(prediction_counts),
                'insights': insights,
                'retrain_recommended': len(scans) >= self.retrain_threshold
            }
            
        except Exception as e:
            logger.error(f"[!] Pattern analysis failed: {e}")
            return {'error': str(e)}
    
    def retrain_models(self) -> bool:
        """Retrain ML models with accumulated data"""
        logger.info("[*] Self-learning: Starting model retraining...")
        
        try:
            # Import training module
            import subprocess
            import sys
            
            result = subprocess.run(
                [sys.executable, 'train_model.py'],
                capture_output=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.last_retrain = datetime.now().isoformat()
                self.total_scans = 0  # Reset counter
                self._save_stats()
                logger.info("[*] Self-learning: Models retrained successfully!")
                return True
            else:
                logger.error(f"[!] Retraining failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"[!] Retraining error: {e}")
            return False
    
    def get_learning_status(self) -> dict:
        """Get current learning status"""
        patterns = self.analyze_patterns()
        
        return {
            'enabled': True,
            'total_scans': self.total_scans,
            'retrain_threshold': self.retrain_threshold,
            'last_retrain': self.last_retrain,
            'retrain_needed': patterns.get('retrain_recommended', False),
            'patterns': patterns
        }


# Global instance
learning_engine = None


def init_learning_engine(data_dir: str = 'learning_data') -> SelfLearningEngine:
    """Initialize self-learning engine"""
    global learning_engine
    learning_engine = SelfLearningEngine(data_dir)
    return learning_engine


def get_learning_engine() -> SelfLearningEngine:
    """Get learning engine instance"""
    global learning_engine
    if learning_engine is None:
        learning_engine = SelfLearningEngine()
    return learning_engine