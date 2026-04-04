"""
PhishGuard AI - Technical Documentation PDF Generator
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem, HRFlowable, PageBreak
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from datetime import datetime

def create_technical_docs():
    doc = SimpleDocTemplate(
        "PhishGuard_AI_Technical_Documentation.pdf",
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('Title', fontSize=28, textColor=colors.HexColor('#00d4ff'), alignment=1, spaceAfter=10)
    subtitle_style = ParagraphStyle('Subtitle', fontSize=14, textColor=colors.gray, alignment=1, spaceAfter=30)
    
    heading1 = ParagraphStyle('Heading1', fontSize=18, textColor=colors.HexColor('#00d4ff'), spaceBefore=20, spaceAfter=10)
    heading2 = ParagraphStyle('Heading2', fontSize=14, textColor=colors.HexColor('#ffffff'), spaceBefore=15, spaceAfter=8, backColor=colors.HexColor('#1a1a2e'), borderPadding=10)
    heading3 = ParagraphStyle('Heading3', fontSize=12, textColor=colors.HexColor('#00d4ff'), spaceBefore=10, spaceAfter=5)
    
    normal = ParagraphStyle('Normal', fontSize=11, textColor=colors.black, spaceAfter=8, leading=16)
    bullet = ParagraphStyle('Bullet', fontSize=11, textColor=colors.black, spaceAfter=5, leftIndent=20, bulletIndent=10)
    
    # ============ TITLE PAGE ============
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("PHISHGUARD AI", title_style))
    elements.append(Paragraph("Technical Documentation", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    elements.append(Paragraph("Advanced Phishing Detection & Awareness System", ParagraphStyle('Sub', fontSize=14, alignment=1, textColor=colors.black)))
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph("College Science Exhibition 2026", ParagraphStyle('Sub2', fontSize=12, alignment=1, textColor=colors.gray)))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d')}", ParagraphStyle('Date', fontSize=10, alignment=1, textColor=colors.gray)))
    
    # ============ TABLE OF CONTENTS ============
    elements.append(PageBreak())
    elements.append(Paragraph("TABLE OF CONTENTS", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    toc_items = [
        "1. Project Overview",
        "2. Technology Stack",
        "3. Programming Languages",
        "4. Machine Learning Models",
        "5. Database Architecture",
        "6. API Endpoints",
        "7. Security Features",
        "8. Deployment"
    ]
    
    for item in toc_items:
        elements.append(Paragraph(item, ParagraphStyle('TOC', fontSize=12, spaceAfter=8)))
    
    # ============ SECTION 1: PROJECT OVERVIEW ============
    elements.append(PageBreak())
    elements.append(Paragraph("1. PROJECT OVERVIEW", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    overview_text = """
    PhishGuard AI is an intelligent cybersecurity application that uses Machine Learning and Natural Language Processing (NLP) 
    to detect phishing attempts across multiple channels: URLs, Emails, SMS, and Social Media messages.
    """
    elements.append(Paragraph(overview_text, normal))
    
    elements.append(Paragraph("Key Capabilities:", heading3))
    capabilities = [
        "• Real-time phishing URL detection using Random Forest classifier",
        "• Email content analysis with TF-IDF vectorization",
        "• SMS (SMiShing) detection with pattern recognition",
        "• Social media scam detection",
        "• Interactive AI chatbot for cybersecurity assistance",
        "• Gamified learning with quizzes and certificates",
        "• PDF report generation for analyzed content"
    ]
    for cap in capabilities:
        elements.append(Paragraph(cap, bullet))
    
    # ============ SECTION 2: TECHNOLOGY STACK ============
    elements.append(PageBreak())
    elements.append(Paragraph("2. TECHNOLOGY STACK", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    tech_data = [
        ['Category', 'Technology', 'Purpose'],
        ['Frontend', 'HTML5 + CSS3 + JavaScript', 'User Interface & Interactions'],
        ['Backend', 'Python Flask', 'API Server & Business Logic'],
        ['Database', 'SQLite', 'Data Persistence'],
        ['ML Framework', 'Scikit-learn', 'Machine Learning Models'],
        ['NLP', 'TF-IDF Vectorizer', 'Text Feature Extraction'],
        ['PDF Generation', 'ReportLab', 'Report Generation'],
        ['Deployment', 'Render (Gunicorn)', 'Cloud Hosting'],
    ]
    
    tech_table = Table(tech_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(tech_table)
    
    # ============ SECTION 3: PROGRAMMING LANGUAGES ============
    elements.append(PageBreak())
    elements.append(Paragraph("3. PROGRAMMING LANGUAGES", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    # Python
    elements.append(Paragraph("Python (Backend)", heading3))
    elements.append(Paragraph("• Used for: Flask API, ML models, data processing, PDF generation", bullet))
    elements.append(Paragraph("• Libraries: Flask, Scikit-learn, ReportLab, NLTK, Pickle", bullet))
    elements.append(Spacer(1, 10))
    
    # JavaScript
    elements.append(Paragraph("JavaScript (Frontend)", heading3))
    elements.append(Paragraph("• Used for: Interactive UI, API calls, user authentication", bullet))
    elements.append(Paragraph("• Frameworks: Vanilla JS (no framework dependency)", bullet))
    elements.append(Spacer(1, 10))
    
    # HTML/CSS
    elements.append(Paragraph("HTML5 + CSS3 (UI Design)", heading3))
    elements.append(Paragraph("• Used for: Page structure and styling", bullet))
    elements.append(Paragraph("• Features: Responsive design, Dark/Light theme, Animations", bullet))
    elements.append(Spacer(1, 10))
    
    # SQL
    elements.append(Paragraph("SQL (Database)", heading3))
    elements.append(Paragraph("• Used for: Data storage, queries, relationships", bullet))
    elements.append(Paragraph("• Type: SQLite (file-based, no server needed)", bullet))
    
    # ============ SECTION 4: MACHINE LEARNING MODELS ============
    elements.append(PageBreak())
    elements.append(Paragraph("4. MACHINE LEARNING MODELS", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    # URL Model
    elements.append(Paragraph("4.1 URL Phishing Detection Model", heading3))
    elements.append(Paragraph("<b>Algorithm:</b> Random Forest Classifier", normal))
    elements.append(Paragraph("<b>Features Extracted (10 features):</b>", normal))
    
    url_features = [
        "1. URL Length - Longer URLs often suspicious",
        "2. Has HTTPS - Secure connection indicator",
        "3. Has @ Symbol - Common phishing indicator",
        "4. Has IP Address - Suspicious if domain replaced by IP",
        "5. Dash Count - Multiple dashes suspicious",
        "6. Digit Ratio - Ratio of digits to letters",
        "7. Suspicious TLD - .tk, .xyz often used in phishing",
        "8. URL Entropy - Randomness in URL characters",
        "9. Subdomain Count - Multiple subdomains suspicious",
        "10. Brand Mentions - Fake brand names in URL"
    ]
    for feature in url_features:
        elements.append(Paragraph(feature, bullet))
    
    elements.append(Spacer(1, 15))
    
    # Text Model
    elements.append(Paragraph("4.2 Email/Message Text Classification Model", heading3))
    elements.append(Paragraph("<b>Algorithm:</b> TF-IDF + Random Forest", normal))
    elements.append(Paragraph("<b>Features:</b>", normal))
    
    text_features = [
        "• TF-IDF Vectorization - Converts text to numerical features",
        "• Unigrams + Bigrams - Single and double word combinations",
        "• Urgency Words - 'urgent', 'immediately', 'act now'",
        "• Threat Words - 'suspended', 'blocked', 'verify'",
        "• Prize Words - 'won', 'selected', 'congratulations'",
        "• Link Count - Number of URLs in message",
        "• Impersonation Score - Fake brand mentions"
    ]
    for feature in text_features:
        elements.append(Paragraph(feature, bullet))
    
    elements.append(Spacer(1, 15))
    
    # Model Training
    elements.append(Paragraph("4.3 Model Training Process", heading3))
    training_steps = [
        "1. Data Collection - Gathered phishing and legitimate samples",
        "2. Feature Extraction - URL features and TF-IDF vectors",
        "3. Train/Test Split - 80% training, 20% testing",
        "4. Model Training - Random Forest with 100 trees",
        "5. Evaluation - Accuracy, Precision, Recall, F1-Score",
        "6. Serialization - Saved as .pkl files using Pickle"
    ]
    for step in training_steps:
        elements.append(Paragraph(step, bullet))
    
    # ============ SECTION 5: DATABASE ARCHITECTURE ============
    elements.append(PageBreak())
    elements.append(Paragraph("5. DATABASE ARCHITECTURE", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    elements.append(Paragraph("PhishGuard uses SQLite - a file-based relational database.", normal))
    
    elements.append(Paragraph("5.1 Database Schema", heading3))
    
    # Users Table
    elements.append(Paragraph("<b>Table: users</b>", normal))
    users_data = [
        ['Column', 'Type', 'Description'],
        ['id', 'INTEGER', 'Primary key, auto-increment'],
        ['email', 'TEXT', 'Unique email address'],
        ['username', 'TEXT', 'User display name'],
        ['password', 'TEXT', 'SHA256 hashed password'],
        ['full_name', 'TEXT', 'User full name'],
        ['institution', 'TEXT', 'College/Organization'],
        ['created_at', 'TEXT', 'Registration timestamp'],
        ['total_analyses', 'INTEGER', 'Count of analyses performed'],
        ['threats_found', 'INTEGER', 'Count of phishing detected'],
    ]
    
    users_table = Table(users_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
    users_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(users_table)
    elements.append(Spacer(1, 15))
    
    # Analyses Table
    elements.append(Paragraph("<b>Table: analyses</b>", normal))
    analyses_data = [
        ['Column', 'Type', 'Description'],
        ['id', 'INTEGER', 'Primary key, auto-increment'],
        ['user_id', 'INTEGER', 'Foreign key to users'],
        ['analysis_type', 'TEXT', 'URL, Email, or Message'],
        ['content', 'TEXT', 'Analyzed URL or message text'],
        ['prediction', 'TEXT', 'phishing, suspicious, or safe'],
        ['confidence', 'REAL', 'Confidence score (0-1)'],
        ['reasons', 'TEXT', 'JSON list of detection reasons'],
        ['features', 'TEXT', 'JSON object of extracted features'],
        ['created_at', 'TEXT', 'Analysis timestamp'],
    ]
    
    analyses_table = Table(analyses_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
    analyses_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(analyses_table)
    elements.append(Spacer(1, 15))
    
    # OTP Table
    elements.append(Paragraph("<b>Table: otp_codes</b>", normal))
    otp_data = [
        ['Column', 'Type', 'Description'],
        ['id', 'INTEGER', 'Primary key'],
        ['email', 'TEXT', 'User email'],
        ['otp', 'TEXT', '6-digit OTP code'],
        ['expires_at', 'INTEGER', 'Expiry timestamp'],
        ['attempts', 'INTEGER', 'Failed attempt counter'],
    ]
    
    otp_table = Table(otp_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
    otp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(otp_table)
    
    elements.append(PageBreak())
    
    # Data Flow
    elements.append(Paragraph("5.2 Data Flow Diagram", heading3))
    flow_text = """
    User Action → Flask API → Feature Extraction → ML Model → Prediction → Database Storage → Response
    """
    elements.append(Paragraph(flow_text, normal))
    
    elements.append(Spacer(1, 15))
    
    # ============ SECTION 6: API ENDPOINTS ============
    elements.append(Paragraph("6. API ENDPOINTS", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    api_data = [
        ['Endpoint', 'Method', 'Description'],
        ['/auth/register', 'POST', 'User registration'],
        ['/auth/login', 'POST', 'User login'],
        ['/auth/logout', 'POST', 'User logout'],
        ['/api/analyze/url', 'POST', 'Analyze URL for phishing'],
        ['/api/analyze/email', 'POST', 'Analyze email content'],
        ['/api/analyze/message', 'POST', 'Analyze SMS/social message'],
        ['/api/export/pdf', 'POST', 'Generate PDF report'],
        ['/api/user/analyses', 'GET', 'Get user analysis history'],
        ['/api/stats', 'GET', 'Get global statistics'],
        ['/api/chat', 'POST', 'AI chatbot interaction'],
        ['/api/quiz', 'GET', 'Get quiz questions'],
    ]
    
    api_table = Table(api_data, colWidths=[2*inch, 1*inch, 3*inch])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(api_table)
    
    # ============ SECTION 7: SECURITY FEATURES ============
    elements.append(PageBreak())
    elements.append(Paragraph("7. SECURITY FEATURES", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    security_features = [
        "<b>Password Hashing:</b> SHA256 encryption for passwords",
        "<b>OTP Verification:</b> Time-limited 6-digit codes",
        "<b>Rate Limiting:</b> Prevents API abuse (100 requests/minute)",
        "<b>Input Validation:</b> All inputs sanitized before processing",
        "<b>Session Management:</b> Secure Flask sessions",
        "<b>CORS Protection:</b> Cross-origin request control",
        "<b>SQL Injection Prevention:</b> Parameterized queries"
    ]
    
    for feature in security_features:
        elements.append(Paragraph("• " + feature, bullet))
    
    # ============ SECTION 8: DEPLOYMENT ============
    elements.append(PageBreak())
    elements.append(Paragraph("8. DEPLOYMENT", heading1))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    
    elements.append(Paragraph("<b>Hosting Platform:</b> Render", normal))
    elements.append(Paragraph("<b>Server:</b> Gunicorn WSGI Server", normal))
    elements.append(Paragraph("<b>Python Version:</b> 3.11", normal))
    elements.append(Paragraph("<b>Database:</b> SQLite (auto-created on first run)", normal))
    
    elements.append(Spacer(1, 15))
    
    deploy_commands = [
        "<b>Build Command:</b> pip install -r requirements.txt",
        "<b>Start Command:</b> gunicorn app:app --bind 0.0.0.0:$PORT",
        "<b>Environment:</b> Python 3.11"
    ]
    
    for cmd in deploy_commands:
        elements.append(Paragraph(cmd, bullet))
    
    # ============ FOOTER ============
    elements.append(Spacer(1, 1*inch))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff'), spaceAfter=20))
    elements.append(Paragraph("PhishGuard AI - College Science Exhibition 2026", ParagraphStyle('Footer', fontSize=12, alignment=1, textColor=colors.gray)))
    elements.append(Paragraph("Built with ❤️ using Python, Flask, and Scikit-learn", ParagraphStyle('Footer2', fontSize=10, alignment=1, textColor=colors.gray)))
    
    # Build PDF
    doc.build(elements)
    print("Technical documentation PDF created: PhishGuard_AI_Technical_Documentation.pdf")

if __name__ == "__main__":
    create_technical_docs()
