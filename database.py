import sqlite3
import os
import json
import hashlib
from contextlib import contextmanager

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'phishguard.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db():
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                full_name TEXT,
                institution TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                total_analyses INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                quiz_score INTEGER DEFAULT 0,
                quiz_completed INTEGER DEFAULT 0
            )
        ''')
        
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                challenge_date TEXT,
                completed INTEGER DEFAULT 0,
                correct INTEGER DEFAULT 0,
                points INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, challenge_date)
            )
        ''')
        
        print("[*] Database initialized successfully")

def create_user(email, username, password, full_name='', institution=''):
    import hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (email, username, password, full_name, institution)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, username, hashed_password, full_name, institution))
        return cursor.lastrowid

def get_user_by_email(email):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def verify_user(email, password):
    import hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, hashed_password))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_user_stats(user_id, analyses=0, threats=0):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users 
            SET total_analyses = total_analyses + ?,
                threats_found = threats_found + ?
            WHERE id = ?
        ''', (analyses, threats, user_id))

def update_last_login(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        # Check if column exists, add if not
        try:
            cursor.execute('SELECT last_login FROM users LIMIT 1')
        except:
            cursor.execute('ALTER TABLE users ADD COLUMN last_login TEXT')
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))

def update_profile_image(user_id, image_data):
    with get_db() as conn:
        cursor = conn.cursor()
        # Check if column exists, add if not
        try:
            cursor.execute('SELECT profile_image FROM users LIMIT 1')
        except:
            cursor.execute('ALTER TABLE users ADD COLUMN profile_image TEXT')
        cursor.execute('UPDATE users SET profile_image = ? WHERE id = ?', (image_data, user_id))

def save_analysis(user_id, analysis_type, content, prediction, confidence, reasons=None, features=None):
    import json
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analyses (user_id, analysis_type, content, prediction, confidence, reasons, features)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, analysis_type, content, prediction, confidence, 
              json.dumps(reasons) if reasons else None,
              json.dumps(features) if features else None))

def get_user_analyses(user_id, limit=50):
    import json
    with get_db() as conn:
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
            # Handle reasons
            if 'reasons' in r and r['reasons'] is not None:
                val = r['reasons']
                if isinstance(val, str):
                    try:
                        r['reasons'] = json.loads(val)
                    except:
                        r['reasons'] = []
                elif isinstance(val, list):
                    r['reasons'] = val
                else:
                    r['reasons'] = []
            else:
                r['reasons'] = []
                
            # Handle features
            if 'features' in r and r['features'] is not None:
                val = r['features']
                if isinstance(val, str):
                    try:
                        r['features'] = json.loads(val)
                    except:
                        r['features'] = {}
                elif isinstance(val, dict):
                    r['features'] = val
                else:
                    r['features'] = {}
            else:
                r['features'] = {}
                
            results.append(r)
        return results

def get_analysis_by_id(analysis_id):
    import json
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
        row = cursor.fetchone()
        if row:
            r = dict(row)
            # Handle reasons - could be string, list, or None
            if 'reasons' in r and r['reasons'] is not None:
                val = r['reasons']
                if isinstance(val, str):
                    try:
                        r['reasons'] = json.loads(val)
                    except:
                        r['reasons'] = []
                elif isinstance(val, list):
                    r['reasons'] = val
                else:
                    r['reasons'] = []
            else:
                r['reasons'] = []
                
            # Handle features - could be string, dict, or None  
            if 'features' in r and r['features'] is not None:
                val = r['features']
                if isinstance(val, str):
                    try:
                        r['features'] = json.loads(val)
                    except:
                        r['features'] = {}
                elif isinstance(val, dict):
                    r['features'] = val
                else:
                    r['features'] = {}
            else:
                r['features'] = {}
                
            return r
        return None

def save_quiz_result(user_id, score, total, category='', difficulty=''):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO quiz_results (user_id, score, total_questions, category, difficulty)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, score, total, category, difficulty))
        
        cursor.execute('''
            UPDATE users 
            SET quiz_completed = quiz_completed + 1,
                quiz_score = quiz_score + ?
            WHERE id = ?
        ''', (score, user_id))

def get_user_quiz_history(user_id, limit=20):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM quiz_results 
            WHERE user_id = ? 
            ORDER BY completed_at DESC 
            LIMIT ?
        ''', (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]

def award_badge(user_id, badge_name, badge_icon=''):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO badges (user_id, badge_name, badge_icon)
            VALUES (?, ?, ?)
        ''', (user_id, badge_name, badge_icon))

def get_user_badges(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM badges WHERE user_id = ?', (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_user_stats(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return None
        
        cursor.execute('SELECT COUNT(*) as count FROM analyses WHERE user_id = ?', (user_id,))
        analyses_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM analyses WHERE user_id = ? AND prediction = "phishing"', (user_id,))
        phishing_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM quiz_results WHERE user_id = ?', (user_id,))
        quiz_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT AVG(score * 100.0 / total_questions) as avg FROM quiz_results WHERE user_id = ?', (user_id,))
        avg_score = cursor.fetchone()['avg'] or 0
        
        cursor.execute('SELECT COUNT(*) as count FROM badges WHERE user_id = ?', (user_id,))
        badges_count = cursor.fetchone()['count']
        
        return {
            'total_analyses': analyses_count,
            'phishing_detected': phishing_count,
            'quiz_attempts': quiz_count,
            'quiz_avg_score': round(avg_score, 1),
            'badges_earned': badges_count
        }

# OTP Management Functions
def save_otp(email, otp, expires_in=60):
    import time
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM otp_codes WHERE email = ?', (email,))
        cursor.execute('''
            INSERT INTO otp_codes (email, otp, created_at, expires_at, attempts)
            VALUES (?, ?, ?, ?, 0)
        ''', (email, otp, int(time.time()), int(time.time()) + expires_in))
        return True

def verify_otp(email, otp):
    import time
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM otp_codes WHERE email = ?', (email,))
        record = cursor.fetchone()
        if not record:
            return {'valid': False, 'error': 'OTP not found'}
        
        current_time = int(time.time())
        if current_time > record['expires_at']:
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

def get_otp_expiry(email):
    import time
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT expires_at FROM otp_codes WHERE email = ?', (email,))
        record = cursor.fetchone()
        if record:
            remaining = record['expires_at'] - int(time.time())
            return max(0, remaining)
        return 0

def init_otp_table():
    with get_db() as conn:
        cursor = conn.cursor()
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
        conn.commit()

if __name__ == '__main__':
    init_db()
    init_otp_table()
    print("[*] Database setup complete")
