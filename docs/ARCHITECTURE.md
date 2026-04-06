# PhishGuard AI - Enterprise Cybersecurity Platform
# Industry-Level Architecture

## Project Structure
```
phishguard_ai/
├── app.py                      # Main Flask entry point
├── config.py                   # Configuration management
├── requirements.txt            # Dependencies
├── runtime.txt                 # Python version
├── Dockerfile                  # Docker container
├── docker-compose.yml          # Docker orchestration
├── .env.example                # Environment variables template
│
├── backend/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py           # API routes
│   │   ├── auth.py             # JWT authentication
│   │   ├── analysis.py         # Analysis endpoints
│   │   └── health.py           # Health check
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── ml_service.py       # ML model management
│   │   ├── threat_intel.py     # Threat intelligence APIs
│   │   ├── risk_engine.py      # Risk scoring engine
│   │   ├── sandbox.py          # Sandbox simulation
│   │   └── explainer.py        # Explainable AI
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── url_classifier.py   # URL ML model
│   │   ├── email_classifier.py # Email NLP model
│   │   └── train.py            # Model training
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── db_manager.py      # Database operations
│   │   └── migrations/        # DB migrations
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logger.py          # Logging
│       ├── validators.py      # Input validation
│       └── helpers.py         # Helper functions
│
├── ml_models/
│   ├── url_model.pkl          # Trained URL model
│   ├── email_model.pkl        # Trained email model
│   └── scalers/               # Feature scalers
│
├── static/
│   ├── css/
│   │   ├── main.css           # Main styles
│   │   ├── dashboard.css      # Dashboard styles
│   │   └── animations.css     # Animations
│   │
│   ├── js/
│   │   ├── app.js             # Main app
│   │   ├── dashboard.js       # Dashboard logic
│   │   ├── analyzer.js        # Analysis UI
│   │   ├── charts.js          # Chart.js integration
│   │   └── auth.js            # Auth handling
│   │
│   ├── assets/
│   │   └── images/
│   │
│   ├── index.html             # Main dashboard
│   ├── login.html             # Login page
│   ├── dashboard.html         # Protected dashboard
│   └── scan.html              # Scanner page
│
├── templates/
│   ├── base.html
│   ├── auth/
│   ├── dashboard/
│   └── reports/
│
├── tests/
│   ├── test_api.py
│   ├── test_ml.py
│   └── test_services.py
│
└── docs/
    ├── API.md
    ├── ARCHITECTURE.md
    └── DEPLOYMENT.md
```

## Core Technologies
| Component | Technology |
|-----------|-----------|
| Backend | Flask + Python 3.11 |
| ML Models | Scikit-learn, TensorFlow |
| Database | PostgreSQL (production), SQLite (dev) |
| Authentication | JWT + Flask-Login |
| API Docs | Flask-RESTX (Swagger) |
| Docker | Multi-stage builds |
| Frontend | Vanilla JS + Chart.js |

## Key Features Implemented
1. Multi-model ML system (URL + Email)
2. Risk Scoring Engine (0-100)
3. Threat Intelligence (VirusTotal, PhishTank)
4. Explainable AI with detailed reasoning
5. JWT Authentication
6. Sandbox Simulation
7. Docker deployment ready