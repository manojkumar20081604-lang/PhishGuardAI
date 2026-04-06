"""
PhishGuard AI - Configuration Management
Industry-Grade Settings
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base Configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-secret-key-2024-prod')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-2024')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # ML Models
    MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_models')
    URL_MODEL_PATH = os.path.join(MODELS_DIR, 'url_model.pkl')
    EMAIL_MODEL_PATH = os.environ.get('EMAIL_MODEL_PATH', os.path.join(MODELS_DIR, 'email_model.pkl'))
    
    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY', '')
    
    # OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    
    # SMTP
    SMTP_EMAIL = os.environ.get('SMTP_EMAIL', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    
    # Rate Limiting
    RATE_LIMIT_MAX_REQUESTS = int(os.environ.get('RATE_LIMIT_MAX', 100))
    RATE_LIMIT_WINDOW = int(os.environ.get('RATE_LIMIT_WINDOW', 60))
    
    # Sandbox
    SANDBOX_TIMEOUT = int(os.environ.get('SANDBOX_TIMEOUT', 30))
    MAX_URL_LENGTH = 2048
    
    # Self-Learning
    AUTO_RETRAIN_THRESHOLD = int(os.environ.get('AUTO_RETRAIN_THRESHOLD', 1000))
    RETRAIN_INTERVAL_DAYS = int(os.environ.get('RETRAIN_INTERVAL_DAYS', 7))


class DevelopmentConfig(Config):
    """Development Configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production Configuration"""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phishguard_prod.db')


class TestingConfig(Config):
    """Testing Configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, DevelopmentConfig)