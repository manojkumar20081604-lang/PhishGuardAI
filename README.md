# 🛡️ PhishGuard AI - Advanced Phishing Detection & Awareness System

### College Science Exhibition 2026 | AI + Cybersecurity Project

---

## 🎯 Project Overview

PhishGuard AI is an intelligent cybersecurity tool that uses **Machine Learning** and **NLP** to detect phishing attempts in:
- 🔗 **URLs** — Feature-based analysis with Random Forest
- 📧 **Emails** — NLP text classification with TF-IDF
- 💬 **Social Media Messages** — Scam pattern detection
- 📱 **SMS (SMiShing)** — Mobile phishing detection

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🤖 AI-Powered Detection | Random Forest + TF-IDF NLP models |
| 📊 Explainable AI | Every verdict shows exact reasons |
| 🔒 Secure Login | OTP-based authentication |
| 🔑 Forgot Password | Password reset with OTP verification |
| 🔐 3-Attempt Lockout | Security against brute force |
| 💾 Permanent History | All scans saved forever, view anytime |
| 📜 PDF Reports | Download analysis reports |
| 👁️ View Analysis | View full details of any past scan |
| 🏆 Certificates | Earn certificates after quiz |
| 📱 PWA Support | Install as mobile app |
| 🎮 Gamification | Badges, achievements, quizzes |
| 🧩 Phishing Simulator | Practice detecting phishing in real scenarios |
| 📹 Educational Videos | YouTube videos for learning |
| 🤖 AI Chatbot | GPT-4 powered cybersecurity assistant |
| 📚 Technical Docs | Auto-generated project documentation PDF |
| 🌓 Dark/Light Theme | User preference toggle |
| 🎵 Background Music | Ambient music while using |
| 👤 Persistent Avatar | Avatar stays after logout |

---

## 🚀 Quick Start

### Local Development

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/PhishGuard---AI.git
cd PhishGuard---AI

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the server
python app.py

# 4. Open in browser
# http://localhost:5000
```

### Deploy to Render

1. Push to GitHub
2. Create new Web Service on Render
3. Connect repository
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn app:app --bind 0.0.0.0:$PORT`

---

## 📁 Project Structure

```
phishguard/
├── app.py              # Flask API server
├── index.html         # Main dashboard
├── login.html         # Login/Register page
├── main.js            # Main application logic
├── database.py        # SQLite database
├── style.css          # Main styles
├── login.js           # Login logic
├── login.css          # Login styles
├── generate_docs.py   # Technical documentation PDF
├── models/            # ML models
│   ├── url_model.pkl
│   └── text_model.pkl
├── static/            # Static assets
└── requirements.txt
```

---

## 🔬 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, JavaScript |
| Backend | Python Flask |
| ML Models | Scikit-learn (Random Forest) |
| NLP | TF-IDF Vectorizer |
| Database | SQLite |
| AI Chatbot | OpenAI GPT-4o-mini |
| Deployment | Render |

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/url` | POST | Analyze URL for phishing |
| `/api/analyze/email` | POST | Analyze email content |
| `/api/analyze/message` | POST | Analyze social media message |
| `/api/history` | GET | Get scan history |
| `/api/user/analyses` | GET | Get user's saved analyses |
| `/api/analysis/<id>` | GET | Get single analysis details |
| `/api/stats` | GET | Get detection statistics |
| `/api/chat` | POST | AI Chatbot (GPT-4) |
| `/api/export/pdf` | POST | Export PDF report |
| `/api/forgot-password` | POST | Send password reset OTP |
| `/api/reset-password` | POST | Reset password with OTP |
| `/api/send-otp` | POST | Send OTP code |
| `/api/verify-otp` | POST | Verify OTP code |
| `/auth/register` | POST | User registration |
| `/auth/login` | POST | User login |
| `/auth/logout` | POST | User logout |

---

## 🎓 For College Exhibition

### Demo Ideas:
1. **Live URL Analysis** - Analyze famous phishing URLs
2. **Email Deep Dive** - Show NLP feature extraction
3. **Quiz Challenge** - Let judges test their knowledge
4. **Certificate Generation** - Show gamification feature
5. **Offline Demo** - Disconnect internet, show client-side working
6. **AI Chatbot** - Interactive cybersecurity assistant with GPT-4
7. **Educational Videos** - Watch cybersecurity awareness videos
8. **Password Reset** - Show secure OTP-based authentication

### ML Model Features:
1. **URL Analysis** (10+ features):
   - URL length, HTTPS presence
   - @ symbol, IP address
   - Dash count, digit ratio
   - Suspicious TLDs, subdomain count

2. **Text Analysis**:
   - TF-IDF with bigrams
   - Urgency phrase detection
   - Link counting
   - Impersonation detection

### Presentation Points:
1. "Our AI uses 10+ URL features for detection"
2. "TF-IDF with bigrams for text classification"
3. "Explainable AI - we show WHY it's phishing"
4. "Works offline - perfect for demos"
5. "Gamification increases user engagement"
6. "Persistent user experience - avatar and preferences saved"
7. "GPT-4 powered chatbot for cybersecurity Q&A"
8. "Secure OTP-based authentication with 3-attempt lockout"

---

## 🔐 Security Features

- **SHA256 Password Hashing** - Secure password storage
- **OTP Verification** - 6-digit codes with 60s expiry
- **3-Attempt Lockout** - Prevents brute force attacks
- **Session Management** - Secure Flask sessions
- **Rate Limiting** - API abuse protection

---

## 📝 License

MIT License - Educational Use

---

## 👨‍💻 Authors

College Students - Computer Science Department
