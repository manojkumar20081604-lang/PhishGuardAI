-- Phishing Detection Database Setup
-- Run this in MySQL to create the database

CREATE DATABASE IF NOT EXISTS phishing_detection;
USE phishing_detection;

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    institution VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Sessions table for user sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token)
);

-- Main analysis history table
CREATE TABLE IF NOT EXISTS analysis_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    analysis_type ENUM('url', 'email', 'social_media', 'sms') NOT NULL,
    input_text TEXT NOT NULL,
    prediction VARCHAR(20) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL,
    threat_level VARCHAR(20),
    detected_features TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    INDEX idx_analysis_type (analysis_type),
    INDEX idx_prediction (prediction),
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- URL analysis details
CREATE TABLE IF NOT EXISTS url_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    history_id INT NOT NULL,
    url_length INT,
    has_https BOOLEAN,
    has_ip_address BOOLEAN,
    has_suspicious_symbols BOOLEAN,
    subdomain_count INT,
    digit_count INT,
    special_char_count INT,
    suspicious_tld VARCHAR(20),
    FOREIGN KEY (history_id) REFERENCES analysis_history(id) ON DELETE CASCADE
);

-- Email analysis details
CREATE TABLE IF NOT EXISTS email_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    history_id INT NOT NULL,
    urgency_word_count INT,
    link_count INT,
    grammar_issues INT,
    sender_suspicious BOOLEAN,
    attachment_present BOOLEAN,
    FOREIGN KEY (history_id) REFERENCES analysis_history(id) ON DELETE CASCADE
);

-- Social media analysis details
CREATE TABLE IF NOT EXISTS social_media_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    history_id INT NOT NULL,
    platform VARCHAR(20),
    fake_offer_detected BOOLEAN,
    scam_pattern_count INT,
    impersonation_score DECIMAL(5,2),
    FOREIGN KEY (history_id) REFERENCES analysis_history(id) ON DELETE CASCADE
);

-- SMS analysis details
CREATE TABLE IF NOT EXISTS sms_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    history_id INT NOT NULL,
    smishing_score INT,
    bank_mention INT,
    reward_mention INT,
    has_otp_request BOOLEAN,
    FOREIGN KEY (history_id) REFERENCES analysis_history(id) ON DELETE CASCADE
);

-- Educational tips and awareness
CREATE TABLE IF NOT EXISTS awareness_tips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    tip_title VARCHAR(200) NOT NULL,
    tip_content TEXT NOT NULL,
    example_text TEXT,
    is_demo BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Quiz questions for gamified learning
CREATE TABLE IF NOT EXISTS quiz_questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    option_a VARCHAR(255) NOT NULL,
    option_b VARCHAR(255) NOT NULL,
    option_c VARCHAR(255) NOT NULL,
    option_d VARCHAR(255) NOT NULL,
    correct_answer CHAR(1) NOT NULL,
    explanation TEXT,
    difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
    category VARCHAR(50) DEFAULT 'general',
    INDEX idx_category (category)
);

-- User quiz attempts
CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    score INT NOT NULL,
    total_questions INT NOT NULL,
    time_taken INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- User bookmarks/saved items
CREATE TABLE IF NOT EXISTS user_bookmarks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    analysis_id INT,
    bookmark_type ENUM('analysis', 'tip', 'example') NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id) ON DELETE CASCADE
);

-- Insert default awareness tips
INSERT INTO awareness_tips (category, tip_title, tip_content, is_demo) VALUES
-- URL tips
('url', 'Always Check the URL', 'Phishing sites often use misspelled domains like "g00gle.com" or "paypa1.com". Always double-check the spelling before entering credentials.', TRUE),
('url', 'Look for HTTPS', 'Secure websites use HTTPS (with the lock icon). However, scammers can also use HTTPS, so this alone does not guarantee safety.', TRUE),
('url', 'Beware of Shortened URLs', 'URL shorteners hide the real destination. Use URL expanders before clicking shortened links.', TRUE),
('url', 'Check for Domain Age', 'Newly registered domains are more likely to be malicious. Check domain age before trusting.', FALSE),

-- Email tips
('email', 'Check the Sender', 'Phishing emails often come from addresses that look legitimate but have subtle misspellings (e.g., support@amaz0n.com).', TRUE),
('email', 'Urgency is a Red Flag', 'Legitimate companies rarely demand immediate action via email. "Your account will be suspended in 24 hours" is a common phishing tactic.', TRUE),
('email', 'Grammar and Spelling', 'Many phishing emails contain grammatical errors or unusual phrasing. Professional companies proofread their communications.', TRUE),
('email', 'Hover Before You Click', 'Hover over links to see the actual URL destination. If it looks suspicious, do not click.', FALSE),

-- Social media tips
('social_media', 'Too Good to Be True', 'If an offer seems too good to be true (free iPhone, lottery win), it probably is a scam.', TRUE),
('social_media', 'Verify Profiles', 'Scammers often impersonate celebrities or companies. Look for verified badges and check follower counts.', TRUE),
('social_media', 'Never Share OTP', 'No legitimate service will ask for your One-Time Password via message or call. This is always a scam.', TRUE),

-- SMS tips
('sms', 'Banks Never Ask for OTP', 'Your bank will NEVER ask for your OTP, PIN, or password via SMS. Any such request is a scam.', TRUE),
('sms', 'Verify Before Acting', 'If you receive a suspicious SMS from your bank, call the official customer care number to verify.', TRUE),
('sms', 'Don\'t Click SMS Links', 'Never click on links in SMS messages, especially from unknown senders. Type the official URL directly.', TRUE),

-- General tips
('general', 'Use Two-Factor Authentication', 'Enable 2FA wherever possible. This adds an extra layer of security even if your password is compromised.', FALSE),
('general', 'Keep Software Updated', 'Regularly update your operating system and applications to patch security vulnerabilities.', FALSE),
('general', 'Use Unique Passwords', 'Never reuse passwords across different accounts. Use a password manager to generate and store unique passwords.', FALSE);

-- Insert quiz questions
INSERT INTO quiz_questions (question, option_a, option_b, option_c, option_d, correct_answer, explanation, difficulty, category) VALUES
('What does HTTPS in a URL indicate?', 'The website is definitely safe', 'The connection is encrypted', 'The website is government approved', 'The website has no viruses', 'B', 'HTTPS means the data between your browser and the website is encrypted, but it does not guarantee the website itself is safe.', 'easy', 'url'),
('Which of these is a sign of a phishing email?', 'Professional formatting', 'Urgent action required', 'Company logo present', 'Proper grammar', 'B', 'Phishing emails often create urgency to pressure you into acting without thinking.', 'easy', 'email'),
('What should you do if you receive an unexpected prize notification?', 'Click the link to claim it', 'Reply with your bank details', 'Ignore and delete', 'Forward to all friends', 'C', 'Unexpected prize notifications are almost always scams. Never share personal information.', 'easy', 'general'),
('Which URL is most likely a phishing site?', 'https://www.paypal.com', 'https://paypal.secure-login.net', 'https://paypal.com/secure', 'https://www.paypal.co.uk', 'B', 'Phishing sites often use domains that look similar to legitimate ones but have extra subdomains.', 'medium', 'url'),
('A bank SMS asks for your OTP to "unlock your account". What should you do?', 'Send the OTP immediately', 'Call the number provided in SMS', 'Ignore and call bank official number', 'Reply with your account number', 'C', 'Banks never ask for OTPs via SMS. This is a smishing scam.', 'medium', 'sms'),
('What does a green padlock icon in the browser mean?', 'Website is 100% safe', 'Connection is encrypted', 'Website is government verified', 'Website won\'t hack you', 'B', 'The padlock only shows the connection is encrypted, not that the website is trustworthy.', 'medium', 'url'),
('Which is a common phishing technique?', 'Using official company email', 'Creating fake urgency', 'Including proper signatures', 'Using correct grammar', 'B', 'Phishers often create artificial urgency to make victims act without thinking.', 'easy', 'general'),
('What is SMiShing?', 'Phishing via social media', 'Phishing via SMS', 'Phishing via email', 'Phishing via phone calls', 'B', 'SMiShing is phishing attacks conducted through SMS messages.', 'easy', 'sms'),
('A message says "Your account will be suspended in 24 hours. Click here to verify." This is:', 'A helpful reminder', 'Likely phishing', 'From your actual bank', 'Safe to click', 'B', 'Legitimate companies rarely threaten suspension via unsolicited messages.', 'medium', 'email'),
('What is the best protection against phishing?', 'Using incognito mode', 'Having antivirus only', 'Being cautious and verifying', 'Turning off computer', 'C', 'Education and vigilance are the best defenses. Always verify before clicking or sharing information.', 'easy', 'general');

-- Stored procedure for getting analysis statistics
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS get_analysis_stats()
BEGIN
    SELECT 
        analysis_type,
        COUNT(*) as total_analyses,
        SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing_count,
        SUM(CASE WHEN prediction = 'Safe' THEN 1 ELSE 0 END) as safe_count,
        AVG(confidence) as avg_confidence
    FROM analysis_history
    GROUP BY analysis_type;
END //

CREATE PROCEDURE IF NOT EXISTS get_user_stats(IN p_user_id INT)
BEGIN
    SELECT 
        COUNT(*) as total_analyses,
        SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN prediction = 'Safe' THEN 1 ELSE 0 END) as safe_detected,
        AVG(confidence) as avg_confidence
    FROM analysis_history
    WHERE user_id = p_user_id;
END //
DELIMITER ;

-- View for recent phishing attempts
CREATE VIEW recent_phishing AS
SELECT 
    id,
    analysis_type,
    LEFT(input_text, 100) as input_preview,
    prediction,
    confidence,
    created_at
FROM analysis_history
WHERE prediction = 'Phishing'
ORDER BY created_at DESC
LIMIT 50;

-- Grant permissions (adjust user as needed)
-- GRANT ALL PRIVILEGES ON phishing_detection.* TO 'phishing_user'@'localhost' IDENTIFIED BY 'your_password';
-- FLUSH PRIVILEGES;
