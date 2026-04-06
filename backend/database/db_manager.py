"""
PhishGuard AI - Database Manager
Industry-grade database operations
"""

import sqlite3
import json
import hashlib
import os
from contextlib import contextmanager
from typing import Optional, List, Dict
from datetime import datetime


class DatabaseManager:
    """Database Manager with SQLite"""
    
    def __init__(self, db_path: str = 'phishguard.db'):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT,
                    password TEXT NOT NULL,
                    full_name TEXT,
                    institution TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT,
                    profile_image TEXT,
                    total_analyses INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    quiz_score INTEGER DEFAULT 0,
                    quiz_completed INTEGER DEFAULT 0
                )
            ''')
            
            # Analyses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    analysis_type TEXT NOT NULL,
                    content TEXT,
                    prediction TEXT NOT NULL,
                    confidence REAL,
                    reasons TEXT,
                    features TEXT,
                    risk_score INTEGER,
                    threat_intel_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Quiz results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    score INTEGER,
                    total_questions INTEGER,
                    category TEXT,
                    difficulty TEXT,
                    completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Badges table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS badges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    badge_name TEXT NOT NULL,
                    badge_icon TEXT,
                    earned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, badge_name)
                )
            ''')
            
            # OTP codes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS otp_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    otp TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    attempts INTEGER DEFAULT 0
                )
            ''')
            
            print("[*] Database initialized successfully")
    
    def create_user(self, email: str, username: str, password: str, 
                    full_name: str = '', institution: str = '') -> int:
        """Create new user"""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, username, password, full_name, institution)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, username, hashed_password, full_name, institution))
            return cursor.lastrowid
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def verify_user(self, email: str, password: str) -> Optional[Dict]:
        """Verify user credentials"""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM users WHERE email = ? AND password = ?',
                (email, hashed_password)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_last_login(self, user_id: int):
        """Update user's last login time"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now().isoformat(), user_id)
            )
    
    def save_analysis(self, user_id: int, analysis_type: str, content: str,
                      prediction: str, confidence: float, reasons: List = None,
                      features: Dict = None, risk_score: int = None,
                      threat_intel_data: Dict = None) -> int:
        """Save analysis to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO analyses 
                (user_id, analysis_type, content, prediction, confidence, reasons, features, risk_score, threat_intel_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, analysis_type, content, prediction, confidence,
                json.dumps(reasons) if reasons else None,
                json.dumps(features) if features else None,
                risk_score,
                json.dumps(threat_intel_data) if threat_intel_data else None
            ))
            
            # Update user stats
            threat_increment = 1 if prediction in ['PHISHING', 'SUSPICIOUS'] else 0
            cursor.execute('''
                UPDATE users SET 
                total_analyses = total_analyses + 1,
                threats_found = threats_found + ?
                WHERE id = ?
            ''', (threat_increment, user_id))
            
            return cursor.lastrowid
    
    def get_user_analyses(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get user's analysis history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM analyses 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                r = dict(row)
                # Parse JSON fields
                r['reasons'] = self._parse_json(r.get('reasons'))
                r['features'] = self._parse_json(r.get('features'))
                r['threat_intel_data'] = self._parse_json(r.get('threat_intel_data'))
                results.append(r)
            
            return results
    
    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict]:
        """Get single analysis by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
            row = cursor.fetchone()
            
            if row:
                r = dict(row)
                r['reasons'] = self._parse_json(r.get('reasons'))
                r['features'] = self._parse_json(r.get('features'))
                r['threat_intel_data'] = self._parse_json(r.get('threat_intel_data'))
                return r
            return None
    
    def get_user_stats(self, user_id: int) -> Dict:
        """Get user statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Total analyses
            cursor.execute('SELECT COUNT(*) as count FROM analyses WHERE user_id = ?', (user_id,))
            total = cursor.fetchone()['count']
            
            # Phishing/suspicious count
            cursor.execute('''
                SELECT COUNT(*) as count FROM analyses 
                WHERE user_id = ? AND prediction IN ('phishing', 'PHISHING', 'suspicious', 'SUSPICIOUS')
            ''', (user_id,))
            threats = cursor.fetchone()['count']
            
            # Quiz attempts
            cursor.execute('SELECT COUNT(*) as count FROM quiz_results WHERE user_id = ?', (user_id,))
            quiz_count = cursor.fetchone()['count']
            
            # Badges
            cursor.execute('SELECT COUNT(*) as count FROM badges WHERE user_id = ?', (user_id,))
            badges = cursor.fetchone()['count']
            
            return {
                'total_analyses': total,
                'threats_found': threats,
                'quiz_attempts': quiz_count,
                'badges_earned': badges
            }
    
    def save_quiz_result(self, user_id: int, score: int, total: int, 
                         category: str = '', difficulty: str = ''):
        """Save quiz result"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO quiz_results (user_id, score, total_questions, category, difficulty)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, score, total, category, difficulty))
            
            cursor.execute('''
                UPDATE users SET 
                quiz_completed = quiz_completed + 1,
                quiz_score = quiz_score + ?
                WHERE id = ?
            ''', (score, user_id))
    
    def award_badge(self, user_id: int, badge_name: str, badge_icon: str = ''):
        """Award badge to user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO badges (user_id, badge_name, badge_icon)
                VALUES (?, ?, ?)
            ''', (user_id, badge_name, badge_icon))
    
    def get_user_badges(self, user_id: int) -> List[Dict]:
        """Get user's badges"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM badges WHERE user_id = ?', (user_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # OTP Management
    def save_otp(self, email: str, otp: str, expires_in: int = 60):
        """Save OTP code"""
        import time
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
            cursor.execute('''
                INSERT INTO otp_codes (email, otp, created_at, expires_at, attempts)
                VALUES (?, ?, ?, ?, 0)
            ''', (email, otp, int(time.time()), int(time.time()) + expires_in))
    
    def verify_otp(self, email: str, otp: str) -> Dict:
        """Verify OTP code"""
        import time
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM otp_codes WHERE email = ?', (email,))
            record = cursor.fetchone()
            
            if not record:
                return {'valid': False, 'error': 'OTP not found'}
            
            if time.time() > record['expires_at']:
                cursor.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
                return {'valid': False, 'error': 'OTP expired'}
            
            if record['attempts'] >= 3:
                cursor.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
                return {'valid': False, 'error': 'Too many attempts'}
            
            if record['otp'] == otp:
                cursor.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
                return {'valid': True}
            
            cursor.execute('UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ?', (email,))
            return {'valid': False, 'error': 'Invalid OTP', 'attempts_left': 3 - record['attempts'] - 1}
    
    def _parse_json(self, value):
        """Parse JSON string safely"""
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except:
            return []


# Global instance
_db_manager = None


def get_db_manager(db_path: str = 'phishguard.db') -> DatabaseManager:
    """Get database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
    return _db_manager