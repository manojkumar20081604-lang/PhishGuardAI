const OfflineAnalyzer = {
    riskyTLDs: ['.xyz', '.top', '.club', '.online', '.site', '.work', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'],
    urlShorteners: ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'shorturl.at'],
    suspiciousKeywords: ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'password', 'signin'],
    brandKeywords: ['paypal', 'amazon', 'google', 'facebook', 'instagram', 'twitter', 'apple', 'microsoft', 'netflix', 'ebay', 'bank', 'chase'],
    urgencyWords: ['urgent', 'immediately', 'right now', 'act now', 'limited time', 'expires', 'suspended', 'verify', 'security alert', 'warning', 'attention'],
    scamPatterns: ['lottery', 'winner', 'prize', 'inheritance', 'prince', 'million dollars', 'wire transfer', 'gift card', 'bitcoin', 'cryptocurrency', 'password', 'ssn'],
    
    analyzeURL(url) {
        const features = this.extractURLFeatures(url);
        const warnings = [];
        const reasons = [];
        let score = 0;
        
        if (features.urlLength > 100) {
            score += 10;
            reasons.push(`URL is unusually long (${features.urlLength} chars)`);
        }
        
        if (!features.hasHTTPS && url.includes('http')) {
            score += 15;
            reasons.push('No HTTPS encryption (insecure)');
        }
        
        if (features.hasIP) {
            score += 25;
            reasons.push('Contains IP address instead of domain');
        }
        
        if (features.hasAtSymbol) {
            score += 30;
            reasons.push('@ symbol - common phishing obfuscation');
        }
        
        if (features.hasRiskyTLD) {
            score += 15;
            reasons.push('Suspicious top-level domain');
        }
        
        if (features.isShortened) {
            score += 20;
            reasons.push('URL shortener - real destination hidden');
        }
        
        if (features.digitRatio > 0.3) {
            score += 15;
            reasons.push(`High digit ratio - possible obfuscation`);
        }
        
        if (features.subdomainDepth > 3) {
            score += 15;
            reasons.push(`Multiple subdomains - suspicious structure`);
        }
        
        if (features.dashCount > 5) {
            score += 15;
            reasons.push('Multiple dashes - mimics legitimate domain');
        }
        
        if (features.encodedChars > 3) {
            score += 20;
            reasons.push('URL encoding hides true destination');
        }
        
        if (features.brandMentionCount > 0 && features.scamCount > 0) {
            score += 15;
            reasons.push('Brand mention + scam keywords = impersonation');
        }
        
        if (features.suspiciousWordCount >= 2) {
            score += 15;
            reasons.push(`Multiple suspicious keywords (${features.suspiciousWordCount})`);
        }
        
        warnings.push(...reasons);
        
        let threatLevel = 'Low';
        let prediction = 'Safe';
        
        if (score > 50) {
            threatLevel = 'High';
            prediction = 'Phishing';
        } else if (score > 25) {
            threatLevel = 'Medium';
            prediction = 'Suspicious';
        }
        
        return {
            prediction,
            confidence: Math.min(Math.max(score, 50), 99),
            threatLevel,
            warnings,
            reasons,
            features,
            offline: true
        };
    },
    
    extractURLFeatures(url) {
        const hasHTTPS = url.startsWith('https://');
        const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
        const hasAtSymbol = url.includes('@');
        const hasRiskyTLD = this.riskyTLDs.some(tld => url.toLowerCase().endsWith(tld));
        const isShortened = this.urlShorteners.some(s => url.toLowerCase().includes(s));
        const dashCount = (url.match(/-/g) || []).length;
        const encodedChars = (url.match(/%/g) || []).length;
        
        const digits = (url.match(/\d/g) || []).length;
        const digitRatio = digits / url.length;
        
        let subdomainDepth = 0;
        const domain = url.split('/')[2] || '';
        const cleanDomain = domain.replace('www.', '');
        const parts = cleanDomain.split('.');
        subdomainDepth = Math.max(0, parts.length - 2);
        
        const urlLower = url.toLowerCase();
        const suspiciousWordCount = this.suspiciousKeywords.filter(w => urlLower.includes(w)).length;
        const brandMentionCount = this.brandKeywords.filter(w => urlLower.includes(w)).length;
        
        return {
            urlLength: url.length,
            hasHTTPS: hasHTTPS ? 1 : 0,
            hasIP: hasIP ? 1 : 0,
            hasAtSymbol: hasAtSymbol ? 1 : 0,
            hasRiskyTLD: hasRiskyTLD ? 1 : 0,
            isShortened: isShortened ? 1 : 0,
            dashCount,
            digitRatio,
            subdomainDepth,
            encodedChars,
            suspiciousWordCount,
            brandMentionCount
        };
    },
    
    analyzeEmail(email) {
        const features = this.extractTextFeatures(email);
        let score = 50;
        const reasons = [];
        
        if (features.urgencyCount >= 3) {
            score += 30;
            reasons.push(`High urgency language (${features.urgencyCount} triggers)`);
        } else if (features.urgencyCount >= 1) {
            score += 15;
            reasons.push('Contains urgency-triggering words');
        }
        
        if (features.scamCount >= 2) {
            score += 25;
            reasons.push(`Multiple scam indicators (${features.scamCount})`);
        } else if (features.scamCount >= 1) {
            score += 10;
            reasons.push('Contains scam-related terms');
        }
        
        if (features.brandMentionCount > 0 && features.scamCount > 0) {
            score += 20;
            reasons.push('Brand impersonation detected');
        }
        
        if (features.linkCount >= 2) {
            score += 20;
            reasons.push(`Multiple suspicious links (${features.linkCount})`);
        } else if (features.linkCount >= 1) {
            score += 10;
            reasons.push('Contains embedded link');
        }
        
        if (features.capsRatio > 0.3) {
            score += 10;
            reasons.push('Excessive capital letters');
        }
        
        if (features.exclamationCount > 3) {
            score += 10;
            reasons.push('Multiple exclamation marks');
        }
        
        let threatLevel = 'Low';
        let prediction = 'Safe';
        
        if (score > 70) {
            threatLevel = 'High';
            prediction = 'Phishing';
        } else if (score > 55) {
            threatLevel = 'Medium';
            prediction = 'Suspicious';
        }
        
        return {
            prediction,
            confidence: Math.min(Math.max(score, 50), 99),
            threatLevel,
            warnings: reasons,
            reasons,
            features,
            offline: true
        };
    },
    
    extractTextFeatures(text) {
        const textLower = text.toLowerCase();
        
        const urgencyCount = this.urgencyWords.filter(w => textLower.includes(w)).length;
        const scamCount = this.scamPatterns.filter(p => textLower.includes(p)).length;
        const brandMentionCount = this.brandKeywords.filter(w => textLower.includes(w)).length;
        const linkCount = (text.match(/https?:\/\/[^\s]+/gi) || []).length;
        
        const capsCount = (text.match(/[A-Z]/g) || []).length;
        const capsRatio = capsCount / text.length;
        
        const exclamationCount = (text.match(/!/g) || []).length;
        
        return {
            urgencyCount,
            scamCount,
            brandMentionCount,
            linkCount,
            capsRatio,
            exclamationCount,
            wordCount: text.split(/\s+/).length
        };
    },
    
    getEducationalExamples() {
        return {
            phishing: [
                {
                    type: 'url',
                    content: 'https://paypa1-secure-login.tk/verify',
                    prediction: 'Phishing',
                    reason: 'Contains "paypa1" (with number 1 instead of L), suspicious TLD, and multiple subdomains'
                },
                {
                    type: 'url',
                    content: 'http://bit.ly/fake-amazon-prize',
                    prediction: 'Phishing',
                    reason: 'URL shortener hides real destination, uses brand name for impersonation'
                },
                {
                    type: 'email',
                    content: 'URGENT: Your bank account has been HACKED! Click here IMMEDIATELY to verify your identity or lose all your money within 24 hours! http://bit.ly/fake-bank-verify',
                    prediction: 'Phishing',
                    reason: 'Creates urgency, threatens loss, contains short link, poor grammar'
                },
                {
                    type: 'sms',
                    content: 'Dear Customer, Your SBI account has been BLOCKED. Call immediately: 9876543210 to unlock. Avoid permanent suspension.',
                    prediction: 'Phishing',
                    reason: 'Banks never ask to call unknown numbers, creates urgency, poor grammar'
                }
            ],
            safe: [
                {
                    type: 'url',
                    content: 'https://www.google.com/search?q=hello',
                    prediction: 'Safe',
                    reason: 'Standard Google domain with HTTPS'
                },
                {
                    type: 'url',
                    content: 'https://github.com/microsoft/vscode',
                    prediction: 'Safe',
                    reason: 'Legitimate GitHub domain, proper structure'
                },
                {
                    type: 'email',
                    content: 'Hi Team, Please find the project report attached. Let me know if you have any questions. Thanks, Sarah',
                    prediction: 'Safe',
                    reason: 'Professional tone, appropriate greeting, no suspicious elements'
                },
                {
                    type: 'sms',
                    content: 'Your OTP for transaction ₹5000 is 123456. Do not share with anyone. -Paytm',
                    prediction: 'Safe',
                    reason: 'Standard OTP format with amount and service name'
                }
            ]
        };
    },
    
    getDemoHistory() {
        const examples = this.getEducationalExamples();
        const history = [];
        
        const now = Date.now();
        
        history.push({
            id: 1,
            analysis_type: 'url',
            input_text: 'https://paypa1-secure-login.tk/verify',
            prediction: 'Phishing',
            confidence: 92,
            threat_level: 'High',
            created_at: new Date(now - 3600000).toISOString()
        });
        
        history.push({
            id: 2,
            analysis_type: 'url',
            input_text: 'https://www.google.com/search?q=hello',
            prediction: 'Safe',
            confidence: 95,
            threat_level: 'Low',
            created_at: new Date(now - 7200000).toISOString()
        });
        
        history.push({
            id: 3,
            analysis_type: 'email',
            input_text: 'URGENT: Your bank account has been HACKED! Click here IMMEDIATELY to verify...',
            prediction: 'Phishing',
            confidence: 88,
            threat_level: 'High',
            created_at: new Date(now - 10800000).toISOString()
        });
        
        history.push({
            id: 4,
            analysis_type: 'sms',
            input_text: 'Dear Customer, Your SBI account has been BLOCKED. Call immediately: 9876543210...',
            prediction: 'Phishing',
            confidence: 85,
            threat_level: 'High',
            created_at: new Date(now - 14400000).toISOString()
        });
        
        history.push({
            id: 5,
            analysis_type: 'email',
            input_text: 'Hi Team, Please find the project report attached. Let me know if you have questions...',
            prediction: 'Safe',
            confidence: 91,
            threat_level: 'Low',
            created_at: new Date(now - 18000000).toISOString()
        });
        
        history.push({
            id: 6,
            analysis_type: 'social_media',
            input_text: 'Congratulations! You\'ve won a FREE iPhone 15! Click here to claim: bit.ly/prize-claim',
            prediction: 'Phishing',
            confidence: 89,
            threat_level: 'High',
            created_at: new Date(now - 21600000).toISOString()
        });
        
        return history;
    }
};

window.OfflineAnalyzer = OfflineAnalyzer;
