// PhishGuard - 200 Cybersecurity Quiz Questions
// Categories: URL, Email, SMS, Social, General
// Difficulties: easy, medium, hard

const questions = [

  // ─────────────────────────────────────────
  // EASY (1–70)
  // ─────────────────────────────────────────

  // URL - Easy
  {
    id: 1,
    category: "URL",
    difficulty: "easy",
    question: "What does 'HTTPS' stand for?",
    options: ["HyperText Transfer Protocol Secure", "High Transfer Protocol System", "HyperText Transport Process Secure", "Hosted Transfer Protocol System"],
    answer: 0
  },
  {
    id: 2,
    category: "URL",
    difficulty: "easy",
    question: "Which part of a URL identifies the website's main address?",
    options: ["Path", "Domain name", "Query string", "Fragment"],
    answer: 1
  },
  {
    id: 3,
    category: "URL",
    difficulty: "easy",
    question: "A URL starting with 'http://' instead of 'https://' means:",
    options: ["It is faster", "The connection is not encrypted", "It is more secure", "It is a government site"],
    answer: 1
  },
  {
    id: 4,
    category: "URL",
    difficulty: "easy",
    question: "Which of the following is a sign of a suspicious URL?",
    options: ["www.google.com", "www.g00gle.com", "www.github.com", "www.amazon.com"],
    answer: 1
  },
  {
    id: 5,
    category: "URL",
    difficulty: "easy",
    question: "What is URL shortening used for in phishing?",
    options: ["To make URLs faster", "To hide the real destination of a link", "To encrypt the website", "To improve SEO"],
    answer: 1
  },
  {
    id: 6,
    category: "URL",
    difficulty: "easy",
    question: "Before clicking a link in an email, you should:",
    options: ["Click it immediately", "Hover over it to see the real URL", "Reply to the email", "Forward it to friends"],
    answer: 1
  },
  {
    id: 7,
    category: "URL",
    difficulty: "easy",
    question: "A padlock icon in the browser address bar means:",
    options: ["The site is 100% safe", "The connection is encrypted", "The site is government-owned", "The site has no viruses"],
    answer: 1
  },
  {
    id: 8,
    category: "URL",
    difficulty: "easy",
    question: "Which of these URLs looks like a phishing attempt targeting PayPal?",
    options: ["www.paypal.com", "www.paypal-secure-login.com", "www.paypal.com/login", "www.paypal.com/help"],
    answer: 1
  },
  {
    id: 9,
    category: "URL",
    difficulty: "easy",
    question: "What is typosquatting?",
    options: ["Hacking using typing speed", "Registering misspelled versions of popular domains", "Blocking websites", "Encrypting URLs"],
    answer: 1
  },
  {
    id: 10,
    category: "URL",
    difficulty: "easy",
    question: "Which domain extension is typically used for commercial websites?",
    options: [".gov", ".edu", ".com", ".mil"],
    answer: 2
  },

  // Email - Easy
  {
    id: 11,
    category: "Email",
    difficulty: "easy",
    question: "What is phishing?",
    options: ["A type of fishing sport", "A cyber attack to steal sensitive information via fake messages", "A method to speed up internet", "A type of computer virus"],
    answer: 1
  },
  {
    id: 12,
    category: "Email",
    difficulty: "easy",
    question: "Which of these is a common sign of a phishing email?",
    options: ["Personalized greeting with your name", "Urgent request to click a link immediately", "Sent from a known colleague", "Contains your account number correctly"],
    answer: 1
  },
  {
    id: 13,
    category: "Email",
    difficulty: "easy",
    question: "You receive an email saying 'Your account will be closed in 24 hours.' What should you do?",
    options: ["Click the link and log in", "Contact the company directly through their official website", "Reply with your password", "Ignore and delete"],
    answer: 1
  },
  {
    id: 14,
    category: "Email",
    difficulty: "easy",
    question: "A legitimate bank will NEVER ask you to:",
    options: ["Send you a receipt", "Provide your PIN via email", "Update your address online", "Send you a new card"],
    answer: 1
  },
  {
    id: 15,
    category: "Email",
    difficulty: "easy",
    question: "What is 'spam' email?",
    options: ["Emails from your boss", "Unsolicited bulk email often containing ads or scams", "Encrypted email", "Email with attachments"],
    answer: 1
  },
  {
    id: 16,
    category: "Email",
    difficulty: "easy",
    question: "Which email sender looks suspicious?",
    options: ["support@amazon.com", "support@amaz0n-help.ru", "noreply@google.com", "info@paypal.com"],
    answer: 1
  },
  {
    id: 17,
    category: "Email",
    difficulty: "easy",
    question: "An email claiming you won a lottery you never entered is most likely:",
    options: ["Real — claim your prize!", "A phishing or scam attempt", "A government notification", "A tax refund"],
    answer: 1
  },
  {
    id: 18,
    category: "Email",
    difficulty: "easy",
    question: "What should you do if you receive a suspicious email attachment?",
    options: ["Open it to check", "Do not open it; scan with antivirus or delete", "Forward it to friends", "Print it out"],
    answer: 1
  },
  {
    id: 19,
    category: "Email",
    difficulty: "easy",
    question: "Poor grammar and spelling in an email is often a sign of:",
    options: ["A casual sender", "A phishing attempt", "A high-priority message", "An automated system"],
    answer: 1
  },
  {
    id: 20,
    category: "Email",
    difficulty: "easy",
    question: "What is the safest action when an email asks for your password?",
    options: ["Provide it if the email looks official", "Never provide your password via email", "Provide it only if asked twice", "Send a hint instead"],
    answer: 1
  },

  // SMS - Easy
  {
    id: 21,
    category: "SMS",
    difficulty: "easy",
    question: "What is 'smishing'?",
    options: ["A cooking technique", "Phishing attacks carried out via SMS text messages", "A software bug", "A type of firewall"],
    answer: 1
  },
  {
    id: 22,
    category: "SMS",
    difficulty: "easy",
    question: "You receive an SMS: 'Your package is held. Click here: bit.ly/xj8k2'. You should:",
    options: ["Click immediately to get your package", "Verify through the official courier website", "Reply with your address", "Call the number in the SMS"],
    answer: 1
  },
  {
    id: 23,
    category: "SMS",
    difficulty: "easy",
    question: "A text message claiming to be from your bank asks for your OTP. This is:",
    options: ["Normal bank procedure", "A smishing attack", "A security check", "An account upgrade"],
    answer: 1
  },
  {
    id: 24,
    category: "SMS",
    difficulty: "easy",
    question: "Which is a red flag in an SMS message?",
    options: ["Message from a saved contact", "Urgency + suspicious link + unknown sender", "Delivery confirmation from Amazon", "Bank balance alert"],
    answer: 1
  },
  {
    id: 25,
    category: "SMS",
    difficulty: "easy",
    question: "OTP stands for:",
    options: ["One Time Password", "Online Transfer Protocol", "Open Text Pass", "Operator Transfer PIN"],
    answer: 0
  },
  {
    id: 26,
    category: "SMS",
    difficulty: "easy",
    question: "Should you ever share an OTP received on your phone with anyone?",
    options: ["Yes, if they claim to be from your bank", "No, never share OTPs with anyone", "Yes, if it's an emergency", "Only with family members"],
    answer: 1
  },
  {
    id: 27,
    category: "SMS",
    difficulty: "easy",
    question: "A text says 'You've won Rs 10,000! Reply YES to claim.' What is this most likely?",
    options: ["A real prize", "A smishing or scam attempt", "A government scheme", "A bank cashback"],
    answer: 1
  },
  {
    id: 28,
    category: "SMS",
    difficulty: "easy",
    question: "What should you do if you accidentally click a suspicious SMS link?",
    options: ["Continue using your phone normally", "Disconnect from internet, scan for malware, change passwords", "Reply to the SMS", "Restart your phone once"],
    answer: 1
  },
  {
    id: 29,
    category: "SMS",
    difficulty: "easy",
    question: "Smishing attacks often create a sense of:",
    options: ["Humor", "Urgency or fear", "Excitement", "Boredom"],
    answer: 1
  },
  {
    id: 30,
    category: "SMS",
    difficulty: "easy",
    question: "Which government body in India handles cybercrime complaints?",
    options: ["RBI", "CERT-In / cybercrime.gov.in", "SEBI", "TRAI"],
    answer: 1
  },

  // Social - Easy
  {
    id: 31,
    category: "Social",
    difficulty: "easy",
    question: "What is social engineering in cybersecurity?",
    options: ["Building social media apps", "Manipulating people psychologically to reveal confidential information", "Engineering social networks", "Hacking using social media APIs"],
    answer: 1
  },
  {
    id: 32,
    category: "Social",
    difficulty: "easy",
    question: "A stranger on Instagram DMs you asking for your phone number and address. You should:",
    options: ["Share it — they seem friendly", "Refuse and block if suspicious", "Share only your phone number", "Ask them why first, then share"],
    answer: 1
  },
  {
    id: 33,
    category: "Social",
    difficulty: "easy",
    question: "What is 'catfishing'?",
    options: ["Phishing using cat-themed emails", "Creating a fake online identity to deceive someone", "A type of network attack", "Fishing for passwords in databases"],
    answer: 1
  },
  {
    id: 34,
    category: "Social",
    difficulty: "easy",
    question: "Posting your vacation dates publicly on social media can:",
    options: ["Get you more followers", "Alert potential burglars that your home is empty", "Improve your social rank", "Help your friends plan visits"],
    answer: 1
  },
  {
    id: 35,
    category: "Social",
    difficulty: "easy",
    question: "Which of these is the safest privacy setting for your social media profile?",
    options: ["Public — everyone can see", "Friends only / Private", "Friends of friends", "No privacy settings"],
    answer: 1
  },
  {
    id: 36,
    category: "Social",
    difficulty: "easy",
    question: "A Facebook friend request from someone you're already friends with may indicate:",
    options: ["They made a new account for fun", "Their account was hacked or cloned", "They want more followers", "A system glitch"],
    answer: 1
  },
  {
    id: 37,
    category: "Social",
    difficulty: "easy",
    question: "What is 'vishing'?",
    options: ["Visual phishing via images", "Voice phishing — scams conducted over phone calls", "Phishing via video calls", "A type of malware"],
    answer: 1
  },
  {
    id: 38,
    category: "Social",
    difficulty: "easy",
    question: "You should use a strong, unique password for each online account because:",
    options: ["It's a government rule", "If one account is hacked, others remain safe", "Websites require it", "It looks more professional"],
    answer: 1
  },
  {
    id: 39,
    category: "Social",
    difficulty: "easy",
    question: "Two-Factor Authentication (2FA) adds security by:",
    options: ["Requiring two passwords", "Requiring a second verification step beyond your password", "Encrypting your account twice", "Blocking all logins from new devices"],
    answer: 1
  },
  {
    id: 40,
    category: "Social",
    difficulty: "easy",
    question: "Which of these is a strong password?",
    options: ["password123", "yourname1999", "Tr!9@kL#2mZ", "123456789"],
    answer: 2
  },

  // General - Easy
  {
    id: 41,
    category: "General",
    difficulty: "easy",
    question: "What does 'malware' mean?",
    options: ["Male software", "Malicious software designed to harm systems", "Mail software", "Management software"],
    answer: 1
  },
  {
    id: 42,
    category: "General",
    difficulty: "easy",
    question: "A firewall is used to:",
    options: ["Speed up your internet", "Block unauthorized access to a network", "Store passwords", "Encrypt emails"],
    answer: 1
  },
  {
    id: 43,
    category: "General",
    difficulty: "easy",
    question: "What is ransomware?",
    options: ["Software that speeds up your PC", "Malware that encrypts your files and demands payment", "Antivirus software", "A type of browser"],
    answer: 1
  },
  {
    id: 44,
    category: "General",
    difficulty: "easy",
    question: "Antivirus software should be:",
    options: ["Installed once and never updated", "Kept updated regularly", "Only used on Windows", "Only needed for emails"],
    answer: 1
  },
  {
    id: 45,
    category: "General",
    difficulty: "easy",
    question: "What is the safest way to connect to the internet in a public place?",
    options: ["Use any free Wi-Fi available", "Use a VPN with a trusted network", "Share someone else's hotspot", "Turn off all security settings"],
    answer: 1
  },
  {
    id: 46,
    category: "General",
    difficulty: "easy",
    question: "VPN stands for:",
    options: ["Virtual Private Network", "Verified Public Node", "Virtual Protocol Network", "Visible Privacy Network"],
    answer: 0
  },
  {
    id: 47,
    category: "General",
    difficulty: "easy",
    question: "You should keep your operating system updated because:",
    options: ["Updates make it look better", "Updates fix security vulnerabilities", "Updates add new games", "Updates make it slower"],
    answer: 1
  },
  {
    id: 48,
    category: "General",
    difficulty: "easy",
    question: "What is a data breach?",
    options: ["When a dam breaks", "Unauthorized access to and theft of confidential data", "A software update", "A firewall failure"],
    answer: 1
  },
  {
    id: 49,
    category: "General",
    difficulty: "easy",
    question: "Which of the following is NOT a cybersecurity best practice?",
    options: ["Using strong passwords", "Sharing your password with close friends", "Enabling 2FA", "Keeping software updated"],
    answer: 1
  },
  {
    id: 50,
    category: "General",
    difficulty: "easy",
    question: "What is the purpose of a CAPTCHA?",
    options: ["To slow down your internet", "To verify you are a human and not a bot", "To encrypt your data", "To block cookies"],
    answer: 1
  },
  {
    id: 51,
    category: "URL",
    difficulty: "easy",
    question: "What does the '@' symbol in a URL usually indicate?",
    options: ["An email address within the URL — often used to mislead users", "A secure connection", "A subdomain", "A file path"],
    answer: 0
  },
  {
    id: 52,
    category: "Email",
    difficulty: "easy",
    question: "What does 'Reply-To' field manipulation in phishing emails do?",
    options: ["Makes email faster", "Redirects your reply to the attacker instead of the real sender", "Blocks spam filters", "Encrypts your reply"],
    answer: 1
  },
  {
    id: 53,
    category: "SMS",
    difficulty: "easy",
    question: "What does it mean when an SMS contains a link to download an APK file?",
    options: ["It's a normal app update", "It could be malware — avoid downloading from unknown SMS sources", "It's from the Play Store", "It's a PDF file"],
    answer: 1
  },
  {
    id: 54,
    category: "Social",
    difficulty: "easy",
    question: "What information should you NEVER share in social media bios?",
    options: ["Your favorite movies", "Full home address and phone number", "Your hobbies", "Your school name"],
    answer: 1
  },
  {
    id: 55,
    category: "General",
    difficulty: "easy",
    question: "What is a Trojan horse in cybersecurity?",
    options: ["A Greek myth reference", "Malicious software disguised as legitimate software", "A type of VPN", "A hardware device"],
    answer: 1
  },
  {
    id: 56,
    category: "General",
    difficulty: "easy",
    question: "What is phishing most commonly delivered through?",
    options: ["Phone calls only", "Email", "Physical letters", "Social media ads only"],
    answer: 1
  },
  {
    id: 57,
    category: "URL",
    difficulty: "easy",
    question: "What does an IP address in a URL (e.g., http://192.168.1.1/login) instead of a domain name suggest?",
    options: ["It is a secure connection", "It may be a phishing or malicious site", "It is a local printer", "It is a government site"],
    answer: 1
  },
  {
    id: 58,
    category: "Email",
    difficulty: "easy",
    question: "Which action is safe when you receive an unexpected email with an attachment?",
    options: ["Open the attachment", "Verify with the sender via another channel before opening", "Forward to all contacts", "Print the attachment"],
    answer: 1
  },
  {
    id: 59,
    category: "Social",
    difficulty: "easy",
    question: "What is 'pretexting' in social engineering?",
    options: ["Sending texts before calling", "Creating a fabricated scenario to manipulate someone into giving information", "Pre-scheduling social media posts", "Blocking unknown callers"],
    answer: 1
  },
  {
    id: 60,
    category: "General",
    difficulty: "easy",
    question: "Which of the following is the best defense against phishing?",
    options: ["Using a slow internet connection", "Security awareness and education", "Never using email", "Using only mobile data"],
    answer: 1
  },
  {
    id: 61,
    category: "URL",
    difficulty: "easy",
    question: "What is a subdomain, and how can it be used in phishing?",
    options: ["A sub-page of a site; cannot be used in phishing", "A prefix before the main domain; attackers use it like 'paypal.evil.com' to trick users", "A domain extension like .com", "A type of cookie"],
    answer: 1
  },
  {
    id: 62,
    category: "Email",
    difficulty: "easy",
    question: "Email spoofing means:",
    options: ["Sending emails quickly", "Forging the sender address to make an email appear from a trusted source", "Blocking emails", "Encrypting an email"],
    answer: 1
  },
  {
    id: 63,
    category: "SMS",
    difficulty: "easy",
    question: "You receive an SMS from 'VM-SBIBNK' asking you to update KYC. What should you do?",
    options: ["Click the link in the SMS", "Visit the official SBI website or branch directly", "Reply with your account number", "Share your Aadhaar number"],
    answer: 1
  },
  {
    id: 64,
    category: "Social",
    difficulty: "easy",
    question: "What is 'baiting' in social engineering?",
    options: ["Fishing in rivers", "Luring victims with something enticing (e.g., a free USB drive containing malware)", "Sending bait emails", "A type of SQL attack"],
    answer: 1
  },
  {
    id: 65,
    category: "General",
    difficulty: "easy",
    question: "What is the most common goal of a phishing attack?",
    options: ["To crash your computer", "To steal credentials, financial info, or personal data", "To speed up your device", "To send you advertisements"],
    answer: 1
  },
  {
    id: 66,
    category: "General",
    difficulty: "easy",
    question: "Which file extension is commonly used by malware in email attachments?",
    options: [".jpg", ".txt", ".exe", ".png"],
    answer: 2
  },
  {
    id: 67,
    category: "URL",
    difficulty: "easy",
    question: "Is it safe to click shortened URLs from unknown senders?",
    options: ["Yes, they are always safe", "No, they can hide malicious destinations", "Only on weekdays", "Yes, if the URL has numbers"],
    answer: 1
  },
  {
    id: 68,
    category: "Email",
    difficulty: "easy",
    question: "What does 'BCC' stand for in email?",
    options: ["Blind Carbon Copy", "Block Contact Copy", "Basic CC", "Bounce Control Copy"],
    answer: 0
  },
  {
    id: 69,
    category: "SMS",
    difficulty: "easy",
    question: "What is a common tactic in smishing involving fake TRAI messages in India?",
    options: ["Claiming your mobile number will be disconnected if you don't verify", "Offering free recharge", "Sending news updates", "Providing weather alerts"],
    answer: 0
  },
  {
    id: 70,
    category: "General",
    difficulty: "easy",
    question: "Which of these helps protect your accounts if your password is stolen?",
    options: ["Having a long email address", "Two-Factor Authentication (2FA)", "Using the same password everywhere", "Logging out after each session only"],
    answer: 1
  },

  // ─────────────────────────────────────────
  // MEDIUM (71–150)
  // ─────────────────────────────────────────

  {
    id: 71,
    category: "URL",
    difficulty: "medium",
    question: "Which URL checking tool can reveal whether a shortened URL is safe?",
    options: ["Google Translate", "VirusTotal or CheckShortURL", "Notepad", "Windows Defender only"],
    answer: 1
  },
  {
    id: 72,
    category: "URL",
    difficulty: "medium",
    question: "What is homograph attack in phishing URLs?",
    options: ["Sending identical emails repeatedly", "Using lookalike Unicode characters in domain names to impersonate legitimate sites", "Copying an entire website", "Redirecting via HTTP"],
    answer: 1
  },
  {
    id: 73,
    category: "URL",
    difficulty: "medium",
    question: "Which URL is most suspicious? A) https://secure.bank.com/login B) https://bank.com.secure-verify.net/login",
    options: ["A — it uses HTTPS", "B — the real domain is secure-verify.net, not bank.com", "Both are equally safe", "Neither is suspicious"],
    answer: 1
  },
  {
    id: 74,
    category: "URL",
    difficulty: "medium",
    question: "What does 'DNS spoofing' do in the context of phishing?",
    options: ["Slows down DNS queries", "Redirects a legitimate domain name to a malicious IP address", "Blocks all DNS requests", "Encrypts DNS traffic"],
    answer: 1
  },
  {
    id: 75,
    category: "URL",
    difficulty: "medium",
    question: "A website uses HTTPS. Does this guarantee it is not a phishing site?",
    options: ["Yes — HTTPS means fully safe", "No — attackers can also get SSL certificates for phishing sites", "Only if it has a padlock", "Yes — all HTTPS sites are verified"],
    answer: 1
  },
  {
    id: 76,
    category: "URL",
    difficulty: "medium",
    question: "What is open redirect vulnerability?",
    options: ["A bug that opens too many tabs", "A flaw that allows attackers to redirect users from a trusted site to a malicious one", "A firewall misconfiguration", "A type of SQL injection"],
    answer: 1
  },
  {
    id: 77,
    category: "URL",
    difficulty: "medium",
    question: "What is the purpose of WHOIS lookup in phishing investigation?",
    options: ["To check internet speed", "To find domain registration details like owner and creation date", "To block a website", "To decrypt HTTPS traffic"],
    answer: 1
  },
  {
    id: 78,
    category: "URL",
    difficulty: "medium",
    question: "Phishing URLs often use which TLD (Top Level Domain) to appear official?",
    options: [".com only", "Any TLD including .gov, .org, or country-specific ones like .in", "Only .net", "Only .edu"],
    answer: 1
  },
  {
    id: 79,
    category: "URL",
    difficulty: "medium",
    question: "What does 'URL encoding' (e.g., %20 for space) do in phishing?",
    options: ["Speeds up loading", "Can be used to obscure malicious characters in a URL to bypass filters", "Compresses the URL", "Adds encryption"],
    answer: 1
  },
  {
    id: 80,
    category: "URL",
    difficulty: "medium",
    question: "A phishing URL contains 'login' and 'secure' in its path. This is:",
    options: ["A sign it is definitely safe", "A common trick to make the URL look legitimate", "Required by Google", "A certificate requirement"],
    answer: 1
  },
  {
    id: 81,
    category: "Email",
    difficulty: "medium",
    question: "What is spear phishing?",
    options: ["Mass phishing emails sent to thousands", "Targeted phishing aimed at a specific individual using personalized information", "Phishing via USB drives", "Phishing via phone calls"],
    answer: 1
  },
  {
    id: 82,
    category: "Email",
    difficulty: "medium",
    question: "What is whaling in cybersecurity?",
    options: ["Phishing targeting marine companies", "Highly targeted phishing attacks aimed at executives or high-profile individuals", "Phishing using whale-themed content", "Blocking large emails"],
    answer: 1
  },
  {
    id: 83,
    category: "Email",
    difficulty: "medium",
    question: "SPF (Sender Policy Framework) helps with:",
    options: ["Encrypting email content", "Verifying that email comes from an authorized mail server for that domain", "Blocking spam keywords", "Compressing email size"],
    answer: 1
  },
  {
    id: 84,
    category: "Email",
    difficulty: "medium",
    question: "What does DKIM stand for in email security?",
    options: ["Dynamic Key Internet Mail", "DomainKeys Identified Mail — a method to validate email authenticity", "Direct Key Infrastructure Management", "Domain Key Internet Mode"],
    answer: 1
  },
  {
    id: 85,
    category: "Email",
    difficulty: "medium",
    question: "DMARC policy in email does what?",
    options: ["Blocks all emails with links", "Tells receiving servers how to handle emails that fail SPF/DKIM checks", "Encrypts email attachments", "Speeds up email delivery"],
    answer: 1
  },
  {
    id: 86,
    category: "Email",
    difficulty: "medium",
    question: "A phishing email uses a legitimate company's logo and formatting. This technique is called:",
    options: ["Logo theft", "Brand impersonation or visual spoofing", "HTML injection", "CSS attack"],
    answer: 1
  },
  {
    id: 87,
    category: "Email",
    difficulty: "medium",
    question: "What is a 'watering hole' attack?",
    options: ["Attacking water utilities", "Compromising a website frequently visited by the target group", "Sending emails to thirsty users", "A denial of service attack on servers"],
    answer: 1
  },
  {
    id: 88,
    category: "Email",
    difficulty: "medium",
    question: "Which email header field is most important for verifying the actual sender?",
    options: ["Subject", "From (display name)", "Return-Path and Received headers", "Date"],
    answer: 2
  },
  {
    id: 89,
    category: "Email",
    difficulty: "medium",
    question: "A 'malicious macro' in an Office document attached to an email can:",
    options: ["Format your document nicely", "Execute harmful code when the document is opened and macros are enabled", "Speed up your computer", "Compress your files"],
    answer: 1
  },
  {
    id: 90,
    category: "Email",
    difficulty: "medium",
    question: "What is 'email harvesting' used for in phishing?",
    options: ["Archiving important emails", "Collecting large lists of email addresses for mass phishing campaigns", "Deleting spam emails", "Backing up email databases"],
    answer: 1
  },
  {
    id: 91,
    category: "SMS",
    difficulty: "medium",
    question: "What technique do attackers use to make an SMS appear to come from a bank's official sender ID?",
    options: ["Network hacking", "SMS spoofing using online tools or SMS gateways", "SIM cloning only", "Bluetooth hijacking"],
    answer: 1
  },
  {
    id: 92,
    category: "SMS",
    difficulty: "medium",
    question: "What is SIM swapping?",
    options: ["Exchanging SIMs with a friend", "Fraudulently transferring a victim's phone number to an attacker's SIM to intercept OTPs", "Upgrading your SIM card", "Using dual-SIM phones"],
    answer: 1
  },
  {
    id: 93,
    category: "SMS",
    difficulty: "medium",
    question: "How do attackers use smishing to bypass 2FA?",
    options: ["They guess the OTP", "They trick victims into sharing OTPs via fake urgent SMS messages", "They hack into the server", "They block the OTP SMS"],
    answer: 1
  },
  {
    id: 94,
    category: "SMS",
    difficulty: "medium",
    question: "A smishing SMS creates urgency to make you:",
    options: ["Think carefully", "Act immediately without verifying, increasing the chance of a mistake", "Contact authorities", "Delete the message"],
    answer: 1
  },
  {
    id: 95,
    category: "SMS",
    difficulty: "medium",
    question: "What is the best technical defense against SIM swap attacks?",
    options: ["Using a prepaid SIM", "Using app-based authenticators (like Google Authenticator) instead of SMS-based 2FA", "Changing your number frequently", "Blocking all SMS"],
    answer: 1
  },
  {
    id: 96,
    category: "SMS",
    difficulty: "medium",
    question: "Attackers send fake job offer SMS messages to collect what type of information?",
    options: ["Your Netflix password", "Personal info like Aadhaar, bank account, and address for fraud", "Your Wi-Fi password", "Your social media login"],
    answer: 1
  },
  {
    id: 97,
    category: "SMS",
    difficulty: "medium",
    question: "What does 'caller ID spoofing' mean in vishing attacks?",
    options: ["Hacking phone hardware", "Faking the displayed phone number to appear as a bank or government agency", "Cloning the victim's SIM", "Recording phone calls illegally"],
    answer: 1
  },
  {
    id: 98,
    category: "SMS",
    difficulty: "medium",
    question: "India's TRAI (Telecom Regulatory Authority of India) introduced which system to combat SMS spoofing?",
    options: ["Blockchain-based SMS filtering / DLT (Distributed Ledger Technology) for SMS", "SMS firewall", "SIM card encryption", "USSD blocking"],
    answer: 0
  },
  {
    id: 99,
    category: "SMS",
    difficulty: "medium",
    question: "An attacker sends an SMS with a link to a fake KYC update page for a UPI app. The primary goal is:",
    options: ["To help you update your KYC", "To steal your UPI PIN and bank credentials", "To send you offers", "To upgrade your app"],
    answer: 1
  },
  {
    id: 100,
    category: "SMS",
    difficulty: "medium",
    question: "What is 'number spoofing' in the context of smishing?",
    options: ["Using fake phone numbers to register SIMs", "Making an SMS appear to originate from a legitimate number when it doesn't", "Blocking incoming SMS", "Duplicating a phone number on two SIMs"],
    answer: 1
  },
  {
    id: 101,
    category: "Social",
    difficulty: "medium",
    question: "What is 'tailgating' in physical social engineering?",
    options: ["Following someone's car too closely", "Gaining unauthorized physical access to a secure area by following an authorized person", "Stealing someone's bag", "Hacking via Bluetooth"],
    answer: 1
  },
  {
    id: 102,
    category: "Social",
    difficulty: "medium",
    question: "OSINT stands for:",
    options: ["Online System Intelligence", "Open Source Intelligence — gathering info from publicly available sources", "Operating System Interface Network Tool", "Offensive Security Intrusion Network Testing"],
    answer: 1
  },
  {
    id: 103,
    category: "Social",
    difficulty: "medium",
    question: "Attackers use OSINT on your social media to craft more convincing phishing attacks. This is because:",
    options: ["Social media is encrypted", "Personal details make phishing emails appear more legitimate and targeted", "OSINT only works on corporate targets", "Social media blocks OSINT tools"],
    answer: 1
  },
  {
    id: 104,
    category: "Social",
    difficulty: "medium",
    question: "What is 'quid pro quo' in social engineering?",
    options: ["A Latin legal term", "Offering a service or benefit in exchange for information or access", "A type of DDoS attack", "A password reset technique"],
    answer: 1
  },
  {
    id: 105,
    category: "Social",
    difficulty: "medium",
    question: "An attacker calls pretending to be IT support and asks you to install remote access software. You should:",
    options: ["Install it — IT support needs access", "Refuse and verify through official IT channels", "Install it only if they know your username", "Give them your IP address"],
    answer: 1
  },
  {
    id: 106,
    category: "Social",
    difficulty: "medium",
    question: "Why is oversharing on LinkedIn dangerous from a phishing perspective?",
    options: ["LinkedIn sells your data", "Attackers use job titles, companies, and colleagues to craft targeted spear phishing attacks", "LinkedIn has weak passwords", "Email addresses are always exposed"],
    answer: 1
  },
  {
    id: 107,
    category: "Social",
    difficulty: "medium",
    question: "What psychological principle do social engineers exploit most frequently?",
    options: ["Logic and reasoning", "Authority, urgency, fear, and trust", "Boredom", "Technical knowledge"],
    answer: 1
  },
  {
    id: 108,
    category: "Social",
    difficulty: "medium",
    question: "A message says: 'This is your bank manager. We need your account details urgently.' What principle is being used?",
    options: ["Scarcity", "Authority + Urgency", "Reciprocity", "Social proof"],
    answer: 1
  },
  {
    id: 109,
    category: "Social",
    difficulty: "medium",
    question: "What is 'dumpster diving' in cybersecurity?",
    options: ["Hacking servers in dumpsters", "Searching through discarded materials (papers, drives) for sensitive information", "A type of SQL attack", "Deleting system logs"],
    answer: 1
  },
  {
    id: 110,
    category: "Social",
    difficulty: "medium",
    question: "Which best describes a 'man-in-the-middle' (MITM) attack in online communication?",
    options: ["One person managing two conversations", "An attacker secretly intercepts and possibly alters communication between two parties", "A network crash caused by overloading", "A firewall misconfiguration"],
    answer: 1
  },
  {
    id: 111,
    category: "General",
    difficulty: "medium",
    question: "What is 'credential stuffing'?",
    options: ["Storing credentials in a USB", "Using leaked username/password pairs from one breach to try logging into other services", "Creating strong passwords", "Encrypting login credentials"],
    answer: 1
  },
  {
    id: 112,
    category: "General",
    difficulty: "medium",
    question: "What is a botnet?",
    options: ["A network of robots", "A network of infected computers controlled by an attacker to conduct coordinated attacks", "A type of antivirus", "A secure server network"],
    answer: 1
  },
  {
    id: 113,
    category: "General",
    difficulty: "medium",
    question: "What is 'pharming'?",
    options: ["Running a farm website", "Redirecting users to fraudulent websites without their knowledge, even when they type the correct URL", "Phishing via pharmacy websites", "Sending emails about farming"],
    answer: 1
  },
  {
    id: 114,
    category: "General",
    difficulty: "medium",
    question: "What is 'session hijacking'?",
    options: ["Attending unauthorized sessions", "Stealing an authenticated session token to gain unauthorized access to a user's account", "Crashing a web session", "Blocking user sessions"],
    answer: 1
  },
  {
    id: 115,
    category: "General",
    difficulty: "medium",
    question: "Which of these is a phishing indicator in a website?",
    options: ["Fast loading speed", "Lookalike domain + urgent prompts + requests for sensitive data", "SSL certificate", "Google Analytics integration"],
    answer: 1
  },
  {
    id: 116,
    category: "General",
    difficulty: "medium",
    question: "Password managers are useful because they:",
    options: ["Share your passwords automatically", "Securely store and generate unique complex passwords for each site", "Send passwords via SMS", "Reset passwords automatically"],
    answer: 1
  },
  {
    id: 117,
    category: "General",
    difficulty: "medium",
    question: "What is 'zero-day exploit'?",
    options: ["A bug found on Day 0 of product launch only", "A vulnerability that is exploited before the vendor has released a patch", "A virus that activates at midnight", "A firewall with no rules"],
    answer: 1
  },
  {
    id: 118,
    category: "General",
    difficulty: "medium",
    question: "What is 'social media phishing'?",
    options: ["Fishing groups on social media", "Using fake social media profiles or messages to steal credentials or spread malware", "Blocking social media", "Creating strong social media passwords"],
    answer: 1
  },
  {
    id: 119,
    category: "General",
    difficulty: "medium",
    question: "Which Indian law deals with cybercrime?",
    options: ["IPC Section 420 only", "Information Technology Act 2000 (IT Act) and its amendments", "Consumer Protection Act", "TRAI Regulations only"],
    answer: 1
  },
  {
    id: 120,
    category: "General",
    difficulty: "medium",
    question: "What should you do immediately after realizing you've given your bank credentials to a phishing site?",
    options: ["Wait to see if anything happens", "Call your bank immediately, change credentials, and monitor for fraudulent transactions", "Delete your email account", "Restart your computer"],
    answer: 1
  },
  {
    id: 121,
    category: "URL",
    difficulty: "medium",
    question: "What is 'punycode' and how is it used in phishing?",
    options: ["A fun coding language for beginners", "Encoding for internationalized domain names — attackers use it to create lookalike URLs using non-ASCII characters", "A URL compression algorithm", "A type of DNS record"],
    answer: 1
  },
  {
    id: 122,
    category: "Email",
    difficulty: "medium",
    question: "What is 'angler phishing'?",
    options: ["Phishing using fishing metaphors", "Attackers impersonating customer support on social media to steal credentials from users seeking help", "Phishing targeting anglers", "Phishing via email attachments only"],
    answer: 1
  },
  {
    id: 123,
    category: "SMS",
    difficulty: "medium",
    question: "Why is SMS-based OTP considered less secure than app-based 2FA?",
    options: ["SMS is slower", "SMS OTPs can be intercepted via SIM swapping, SS7 attacks, or smishing", "App-based 2FA costs money", "SMS doesn't work internationally"],
    answer: 1
  },
  {
    id: 124,
    category: "Social",
    difficulty: "medium",
    question: "What is 'reverse social engineering'?",
    options: ["Building social networks from scratch", "Attacker creates a problem then offers to fix it, gaining the victim's trust and access", "Engineering new social platforms", "Blocking social engineering attempts"],
    answer: 1
  },
  {
    id: 125,
    category: "General",
    difficulty: "medium",
    question: "What does 'CERT-In' stand for?",
    options: ["Central European Response Technology", "Indian Computer Emergency Response Team — India's national cybersecurity agency", "Certificate of Internet", "Cybersecurity Emergency Response Team India"],
    answer: 1
  },
  {
    id: 126,
    category: "URL",
    difficulty: "medium",
    question: "What is a 'drive-by download' associated with malicious URLs?",
    options: ["Downloading files while driving", "Malware automatically downloaded when visiting a compromised URL without user interaction", "Downloading a browser extension", "A fast download from CDN"],
    answer: 1
  },
  {
    id: 127,
    category: "Email",
    difficulty: "medium",
    question: "What is 'email thread hijacking'?",
    options: ["Replying to all in a thread", "Attacker inserts a phishing email into an existing legitimate email thread to gain trust", "Forwarding emails automatically", "Blocking email chains"],
    answer: 1
  },
  {
    id: 128,
    category: "Social",
    difficulty: "medium",
    question: "You see a social media post: '10,000 people liked this tip — always send your OTP to @securebank for verification.' This is:",
    options: ["A trusted banking tip", "A social proof manipulation tactic to steal OTPs", "A real banking procedure", "A government mandate"],
    answer: 1
  },
  {
    id: 129,
    category: "General",
    difficulty: "medium",
    question: "What is the dark web primarily used for in cybercrime?",
    options: ["Secure messaging only", "Buying and selling stolen credentials, malware, and illicit services anonymously", "Streaming media without ads", "Bypassing government firewalls"],
    answer: 1
  },
  {
    id: 130,
    category: "General",
    difficulty: "medium",
    question: "What is 'shoulder surfing'?",
    options: ["A beach activity", "Observing someone's screen or keyboard to steal PINs or passwords", "A network monitoring technique", "A type of SQL injection"],
    answer: 1
  },
  {
    id: 131,
    category: "URL",
    difficulty: "medium",
    question: "What is a 'redirect chain' and why is it used in phishing?",
    options: ["A series of legitimate redirects for SEO", "Multiple URL redirects to mask the final malicious destination and evade URL filters", "A broken link error", "A method to load pages faster"],
    answer: 1
  },
  {
    id: 132,
    category: "Email",
    difficulty: "medium",
    question: "HTML emails can be more dangerous than plain text because:",
    options: ["They use more bandwidth", "They can hide real hyperlink destinations, embed tracking pixels, and run scripts", "They load slower", "Spam filters block them automatically"],
    answer: 1
  },
  {
    id: 133,
    category: "SMS",
    difficulty: "medium",
    question: "An SMS from 'ICICIB' (note one extra letter) claiming your account is blocked is:",
    options: ["Definitely from ICICI Bank", "Likely a spoofed sender ID — a smishing attempt", "An internal bank test", "An RBI notification"],
    answer: 1
  },
  {
    id: 134,
    category: "Social",
    difficulty: "medium",
    question: "What is 'piggybacking' in physical security (different from tailgating)?",
    options: ["Carrying heavy servers", "Gaining unauthorized entry to a restricted area with the willing (but uninformed) help of an authorized person", "Hacking while moving", "Jumping over security gates"],
    answer: 1
  },
  {
    id: 135,
    category: "General",
    difficulty: "medium",
    question: "What is 'lateral movement' after a phishing attack succeeds?",
    options: ["Moving the attacker's server location", "Attacker moves through a network from one system to others to escalate privileges or access more data", "Sending phishing emails to other users", "Updating malware on the victim's system"],
    answer: 1
  },
  {
    id: 136,
    category: "URL",
    difficulty: "medium",
    question: "What does a 'honeypot' URL do in cybersecurity research?",
    options: ["Stores passwords", "Acts as a decoy to attract and study attacker behavior", "Speeds up legit URLs", "Encrypts user data"],
    answer: 1
  },
  {
    id: 137,
    category: "Email",
    difficulty: "medium",
    question: "What is a 'look-alike domain' in phishing?",
    options: ["Two identical websites", "A domain that visually resembles a trusted brand (e.g., arnazon.com vs amazon.com)", "A duplicate server", "An expired domain"],
    answer: 1
  },
  {
    id: 138,
    category: "Social",
    difficulty: "medium",
    question: "A LinkedIn connection you don't know sends you a malware-laden PDF titled 'Career Opportunities 2025'. This is called:",
    options: ["Networking spam", "Spear phishing via social media", "Career advice", "Standard recruitment"],
    answer: 1
  },
  {
    id: 139,
    category: "General",
    difficulty: "medium",
    question: "What is 'identity theft'?",
    options: ["Stealing someone's physical ID card", "Using someone's personal information without consent to commit fraud or other crimes", "Hacking someone's account once", "Copying someone's style"],
    answer: 1
  },
  {
    id: 140,
    category: "General",
    difficulty: "medium",
    question: "What is 'multi-factor authentication' (MFA)?",
    options: ["Using multiple passwords", "A security system requiring two or more verification factors — something you know, have, or are", "Logging in from multiple devices", "Having multiple email accounts"],
    answer: 1
  },
  {
    id: 141,
    category: "URL",
    difficulty: "medium",
    question: "What does 'certificate transparency' help with in phishing detection?",
    options: ["Making SSL certificates invisible", "Publicly logging all SSL certificates so suspicious ones for phishing domains can be detected", "Blocking HTTPS", "Encrypting DNS traffic"],
    answer: 1
  },
  {
    id: 142,
    category: "Email",
    difficulty: "medium",
    question: "What is 'BEC' (Business Email Compromise)?",
    options: ["A business email client", "A scam where attackers impersonate executives to trick employees into wire transfers or data sharing", "Bulk email campaign", "A type of email encryption"],
    answer: 1
  },
  {
    id: 143,
    category: "SMS",
    difficulty: "medium",
    question: "What is 'SS7 attack' in mobile security?",
    options: ["A satellite system hack", "Exploiting vulnerabilities in the Signaling System 7 protocol to intercept SMS and calls", "A 5G network attack", "A SIM card encryption bypass"],
    answer: 1
  },
  {
    id: 144,
    category: "Social",
    difficulty: "medium",
    question: "What is 'impersonation attack' in social engineering?",
    options: ["Copying someone's fashion", "Pretending to be a trusted person (colleague, IT staff, authority) to extract information or access", "Copying a website's design", "A type of DDoS attack"],
    answer: 1
  },
  {
    id: 145,
    category: "General",
    difficulty: "medium",
    question: "What is 'threat intelligence' in cybersecurity?",
    options: ["Making threats to hackers", "Information about current and emerging threats used to prepare and defend against cyber attacks", "A hacker's skill level", "A government surveillance program"],
    answer: 1
  },
  {
    id: 146,
    category: "URL",
    difficulty: "medium",
    question: "What tool can you use to safely preview a URL without visiting it?",
    options: ["Google Translate", "Screenshot tools like urlscan.io or Google Safe Browsing", "Notepad", "DNS lookup only"],
    answer: 1
  },
  {
    id: 147,
    category: "Email",
    difficulty: "medium",
    question: "What is a 'tracking pixel' in phishing emails?",
    options: ["A colorful design element", "A tiny invisible image that notifies the attacker when the email is opened, confirming active addresses", "A pixel art attachment", "An image compression tool"],
    answer: 1
  },
  {
    id: 148,
    category: "SMS",
    difficulty: "medium",
    question: "A fake 'PM-KISAN' SMS asks farmers to update bank details. This targets:",
    options: ["Urban tech workers", "Rural populations using government scheme names to steal banking details", "Students", "Corporate employees"],
    answer: 1
  },
  {
    id: 149,
    category: "Social",
    difficulty: "medium",
    question: "What makes insider threats different from external phishing?",
    options: ["Insiders use better malware", "Insiders already have legitimate access, making detection harder", "Insiders only attack large companies", "Insiders always get caught quickly"],
    answer: 1
  },
  {
    id: 150,
    category: "General",
    difficulty: "medium",
    question: "What is 'sandboxing' in malware analysis?",
    options: ["Playing in a sandbox", "Running suspicious files in an isolated environment to observe behavior without risking the real system", "Building firewall rules", "Encrypting files before opening"],
    answer: 1
  },

  // ─────────────────────────────────────────
  // HARD (151–200)
  // ─────────────────────────────────────────

  {
    id: 151,
    category: "URL",
    difficulty: "hard",
    question: "In machine learning-based phishing URL detection, which feature is most reliable for identifying phishing?",
    options: ["URL length alone", "Lexical features combined with WHOIS age, DNS records, and page content analysis", "Presence of HTTPS", "Number of slashes in URL"],
    answer: 1
  },
  {
    id: 152,
    category: "URL",
    difficulty: "hard",
    question: "How does a 'fast flux' DNS technique help attackers evade phishing takedowns?",
    options: ["Encrypting DNS responses", "Rapidly rotating IP addresses associated with a domain to keep the phishing site alive despite takedowns", "Using multiple domain extensions", "Blocking DNS queries from security researchers"],
    answer: 1
  },
  {
    id: 153,
    category: "URL",
    difficulty: "hard",
    question: "What is 'domain generation algorithm' (DGA) in malware?",
    options: ["An SEO tool for generating domain ideas", "Malware that automatically generates many domain names to use as C2 servers, making blacklisting ineffective", "A WHOIS privacy service", "A DNS caching method"],
    answer: 1
  },
  {
    id: 154,
    category: "URL",
    difficulty: "hard",
    question: "Which HTTP response code is most often associated with a redirect used in phishing chains?",
    options: ["200 OK", "301 Moved Permanently or 302 Found — used to chain redirects through legitimate domains", "404 Not Found", "500 Internal Server Error"],
    answer: 1
  },
  {
    id: 155,
    category: "URL",
    difficulty: "hard",
    question: "Attackers register domains days before phishing campaigns. Why does 'domain age' matter in phishing detection?",
    options: ["Older domains load faster", "Newly registered domains (< 30 days old) are statistically more likely to be phishing sites", "Older domains are more expensive", "Domain age affects HTTPS certificate validity"],
    answer: 1
  },
  {
    id: 156,
    category: "URL",
    difficulty: "hard",
    question: "What is 'IDN homograph attack' and which browser defense exists against it?",
    options: ["Hacking via IDE tools; fixed by updating the IDE", "Using Unicode characters that look like ASCII letters to create lookalike domains; browsers mitigate this by displaying punycode for suspicious mixed-script domains", "A SQL injection via URL; fixed by WAF", "An attack using identical URL paths; fixed by HTTPS"],
    answer: 1
  },
  {
    id: 157,
    category: "URL",
    difficulty: "hard",
    question: "How do attackers abuse Google's own infrastructure for phishing?",
    options: ["They hack Google servers directly", "They use legitimate Google services (Forms, Sites, Drive) to host phishing pages that pass URL filters since google.com is trusted", "They buy Google ads to redirect users", "They exploit Google Translate to mask phishing URLs"],
    answer: 1
  },
  {
    id: 158,
    category: "URL",
    difficulty: "hard",
    question: "What is 'URL fragmentation' in phishing evasion?",
    options: ["Breaking URLs into parts for speed", "Using the URL fragment (#section) to pass parameters that aren't sent to the server but are processed client-side, evading server-side URL scanners", "Compressing long URLs", "Splitting traffic across servers"],
    answer: 1
  },
  {
    id: 159,
    category: "URL",
    difficulty: "hard",
    question: "In phishing detection using Random Forest, what is 'feature importance' referring to?",
    options: ["How important the URL is to the user", "Which URL features (length, special chars, domain age, etc.) most strongly predict phishing classification", "The weight of the neural network", "The server's processing priority"],
    answer: 1
  },
  {
    id: 160,
    category: "URL",
    difficulty: "hard",
    question: "Which Google service can be used to check if a URL is listed in Google's Safe Browsing database?",
    options: ["Google Search Console", "Google Safe Browsing API (Lookup API or Transparency Report)", "Google Analytics", "Google PageSpeed Insights"],
    answer: 1
  },
  {
    id: 161,
    category: "Email",
    difficulty: "hard",
    question: "What is 'BIMI' (Brand Indicators for Message Identification) in email security?",
    options: ["A brand monitoring tool", "A standard that allows brands to display verified logos in email clients, linked to DMARC enforcement, to build trust and reduce impersonation", "An email encryption standard", "A blacklist database"],
    answer: 1
  },
  {
    id: 162,
    category: "Email",
    difficulty: "hard",
    question: "In a BEC attack, the attacker typically compromises which account first?",
    options: ["The CEO's social media", "An executive's email account via phishing, then uses it to send fraudulent wire transfer requests", "The company's DNS server", "The company's website"],
    answer: 1
  },
  {
    id: 163,
    category: "Email",
    difficulty: "hard",
    question: "What is 'adversary-in-the-middle phishing' (AiTM) using tools like Evilginx?",
    options: ["A man-in-the-middle hardware attack", "A phishing technique using a reverse proxy to intercept credentials AND session cookies in real time, bypassing MFA", "A DNS poisoning attack", "A keystroke logging method"],
    answer: 1
  },
  {
    id: 164,
    category: "Email",
    difficulty: "hard",
    question: "How does 'email subaddressing' (using + signs like user+tag@gmail.com) help with phishing detection?",
    options: ["It blocks all phishing emails", "It can help identify which service leaked your email — if user+shopping@gmail.com receives phishing, the 'shopping' service may have been breached", "It encrypts your email", "It blocks tracking pixels"],
    answer: 1
  },
  {
    id: 165,
    category: "Email",
    difficulty: "hard",
    question: "What is 'polyglot file' technique in email attachments?",
    options: ["An attachment in multiple languages", "A file that is simultaneously valid in two formats (e.g., a PDF that is also a JavaScript file), used to evade security scanners", "A multilingual phishing email", "A file that changes language based on location"],
    answer: 1
  },
  {
    id: 166,
    category: "Email",
    difficulty: "hard",
    question: "What is 'living off the land' (LotL) technique in phishing follow-up attacks?",
    options: ["Phishing attacks targeting farmers", "Using legitimate system tools (PowerShell, WMI, certutil) already present on the victim's machine to execute malicious actions, evading detection", "Ransomware targeting agricultural systems", "Using open-source tools for phishing"],
    answer: 1
  },
  {
    id: 167,
    category: "Email",
    difficulty: "hard",
    question: "Why do attackers use legitimate cloud storage services (OneDrive, Dropbox) to host phishing payloads?",
    options: ["They are free services", "Files hosted on trusted domains bypass email security filters that block known malicious domains", "They offer unlimited storage", "They are encrypted end-to-end"],
    answer: 1
  },
  {
    id: 168,
    category: "Email",
    difficulty: "hard",
    question: "What is 'conversation injection' in email phishing?",
    options: ["Injecting code into email clients", "Inserting a phishing email into an existing legitimate email thread by compromising one participant's account", "Modifying email subjects during transit", "A type of SQL injection via email forms"],
    answer: 1
  },
  {
    id: 169,
    category: "Email",
    difficulty: "hard",
    question: "In DMARC, what does a 'p=reject' policy mean?",
    options: ["Reject all incoming emails", "Emails that fail DMARC checks should be rejected and not delivered to the recipient at all", "Reject emails with attachments", "Reject emails from unknown senders"],
    answer: 1
  },
  {
    id: 170,
    category: "Email",
    difficulty: "hard",
    question: "What is 'callback phishing' (telephone-oriented attack delivery — TOAD)?",
    options: ["Phishing via voicemail only", "An email containing no malicious links — instead directing victims to call a phone number where live social engineers complete the attack", "Phishing that calls you back after clicking a link", "Automated robocall phishing"],
    answer: 1
  },
  {
    id: 171,
    category: "SMS",
    difficulty: "hard",
    question: "What is 'SS7 protocol' and why is it inherently vulnerable to interception?",
    options: ["A 5G encryption protocol; vulnerable to quantum attacks", "A 1970s-era telecom signaling protocol with no built-in authentication — attackers with SS7 access can redirect calls/SMS anywhere in the world", "A SIM card protocol; vulnerable only in older phones", "A Wi-Fi protocol; vulnerable to MITM attacks"],
    answer: 1
  },
  {
    id: 172,
    category: "SMS",
    difficulty: "hard",
    question: "In a SIM swap attack, what information do attackers typically gather first via phishing or OSINT?",
    options: ["Your IMEI number only", "Your full name, date of birth, address, and account number — info needed to pass identity verification at the telecom provider", "Your SIM card serial number only", "Your phone's unlock PIN"],
    answer: 1
  },
  {
    id: 173,
    category: "SMS",
    difficulty: "hard",
    question: "What is 'IMSI catching' (Stingray attack) in mobile security?",
    options: ["Hacking IMSI databases", "Using a fake mobile base station device to intercept communications of nearby phones", "A SIM swap variant", "An attack on IMSI numbers in databases"],
    answer: 1
  },
  {
    id: 174,
    category: "SMS",
    difficulty: "hard",
    question: "How does DLT (Distributed Ledger Technology) registration help prevent SMS phishing in India?",
    options: ["It encrypts all SMS messages", "It requires businesses to register sender IDs and templates on a blockchain-based registry, making unauthorized SMS spoofing detectable", "It blocks all marketing SMS", "It adds OTPs to all SMS"],
    answer: 1
  },
  {
    id: 175,
    category: "SMS",
    difficulty: "hard",
    question: "What is 'SMS pumping fraud' and how does it relate to OTP systems?",
    options: ["Sending bulk promotional SMS", "Attackers trigger mass OTP SMS to premium-rate numbers they control, generating revenue from the OTP delivery costs", "Pumping fake reviews via SMS", "Inflating SMS delivery rates"],
    answer: 1
  },
  {
    id: 176,
    category: "SMS",
    difficulty: "hard",
    question: "Which attack involves sending fragmented SMS messages that reassemble into a malicious payload on the device?",
    options: ["SMS spoofing", "SMS fragmentation or binary SMS attacks targeting SMS parsing vulnerabilities in mobile OS", "MMS attack", "Bluetooth SMS injection"],
    answer: 1
  },
  {
    id: 177,
    category: "SMS",
    difficulty: "hard",
    question: "How do attackers exploit 'Silent SMS' (Type 0 SMS) for surveillance?",
    options: ["By sending promotional content silently", "A Type 0 SMS is processed by the phone but never displayed — attackers use it to locate devices or probe networks without the user's knowledge", "By silencing the victim's phone", "By disabling SMS notifications"],
    answer: 1
  },
  {
    id: 178,
    category: "SMS",
    difficulty: "hard",
    question: "What is 'RCS phishing' and why is it more dangerous than traditional SMS phishing?",
    options: ["Rich Content Spam — dangerous because of file sizes", "Rich Communication Services phishing — more dangerous because RCS supports rich media, verified sender IDs (which can be spoofed), and lacks consistent end-to-end encryption", "Restricted Communication Spoofing — dangerous because it bypasses all filters", "Real-time Chat Scamming — dangerous because of speed"],
    answer: 1
  },
  {
    id: 179,
    category: "SMS",
    difficulty: "hard",
    question: "An attacker uses a legitimate telecom API (aggregator) to send phishing SMS at scale with a bank sender ID. What does this exploit?",
    options: ["A weakness in the victim's phone", "Weaknesses in sender ID validation at SMS aggregator level — aggregators may not properly verify who is authorized to use a sender ID", "A flaw in the bank's mobile app", "SS7 protocol directly"],
    answer: 1
  },
  {
    id: 180,
    category: "SMS",
    difficulty: "hard",
    question: "How can mobile malware enhance an SMS phishing attack's success rate?",
    options: ["By making the phone faster", "Malware can intercept OTPs, forward SMS to attackers, suppress security alerts, and even auto-click links — creating a fully automated account takeover chain", "By blocking legitimate SMS", "By encrypting the victim's data first"],
    answer: 1
  },
  {
    id: 181,
    category: "Social",
    difficulty: "hard",
    question: "What is 'deepfake vishing' and why is it a growing threat?",
    options: ["Fake social media profiles using deep learning", "Using AI-generated voice clones of trusted individuals (executives, family members) to conduct voice phishing attacks that are nearly indistinguishable from real calls", "Deep web phishing via voice chat", "AI-generated email phishing"],
    answer: 1
  },
  {
    id: 182,
    category: "Social",
    difficulty: "hard",
    question: "What is 'island hopping' in targeted cyber attacks?",
    options: ["Physically traveling between islands with a hacked laptop", "Compromising a smaller third-party supplier or partner to gain access to the high-value primary target organization", "Hopping between social media platforms", "Moving between encrypted communication channels"],
    answer: 1
  },
  {
    id: 183,
    category: "Social",
    difficulty: "hard",
    question: "What does 'HUMINT' mean in the context of social engineering?",
    options: ["Human Interface Networking Intelligence", "Human Intelligence — gathering information through interpersonal interaction rather than technical means", "Humanitarian Intelligence", "Hybrid Unit Machine Intelligence"],
    answer: 1
  },
  {
    id: 184,
    category: "Social",
    difficulty: "hard",
    question: "How does 'cognitive biases exploitation' work in advanced social engineering?",
    options: ["Hacking the brain with technology", "Attackers deliberately exploit predictable patterns in human thinking (confirmation bias, authority bias, urgency bias) to override critical judgment", "Using cognitive science in building apps", "Training employees using cognitive methods"],
    answer: 1
  },
  {
    id: 185,
    category: "Social",
    difficulty: "hard",
    question: "What is 'access broker' in the cybercrime ecosystem and how do they relate to phishing?",
    options: ["A legitimate IT service", "Criminals who use phishing to gain initial access to organizations, then sell that access to ransomware groups or other attackers on dark web forums", "A penetration testing firm", "A cybersecurity recruiter"],
    answer: 1
  },
  {
    id: 186,
    category: "Social",
    difficulty: "hard",
    question: "What makes 'AI-generated spear phishing' emails harder to detect than traditional spear phishing?",
    options: ["They are sent faster", "AI can generate perfectly grammatical, highly personalized emails using OSINT data at scale — eliminating the spelling errors and generic language that human victims use as red flags", "They bypass all email filters technically", "They come from verified domains automatically"],
    answer: 1
  },
  {
    id: 187,
    category: "Social",
    difficulty: "hard",
    question: "In the 'Cialdini principles of influence', which combination is most commonly weaponized in phishing?",
    options: ["Liking + Commitment", "Authority + Scarcity + Social Proof + Urgency — used simultaneously to overwhelm critical thinking", "Reciprocity only", "Consistency + Liking"],
    answer: 1
  },
  {
    id: 188,
    category: "Social",
    difficulty: "hard",
    question: "What is 'USB drop attack' and what makes it effective?",
    options: ["Dropping USB prices to steal market share", "Leaving malware-infected USB drives in target locations — effective because human curiosity and desire to return 'found' items leads people to plug them in", "Physically destroying USB drives", "A network attack via USB adapters"],
    answer: 1
  },
  {
    id: 189,
    category: "Social",
    difficulty: "hard",
    question: "In corporate phishing simulations, what metric is most predictive of real phishing susceptibility?",
    options: ["Email open rate only", "Credential submission rate (users who not only click but also enter credentials), combined with department and seniority data", "Number of spam reports", "Antivirus detection rate"],
    answer: 1
  },
  {
    id: 190,
    category: "Social",
    difficulty: "hard",
    question: "What is 'pig butchering' (Sha Zhu Pan) scam?",
    options: ["A food industry cyberattack", "A long-term investment fraud where attackers build romantic or friendship trust with victims over weeks or months before convincing them to invest in fake crypto platforms", "A social media hacking method", "A ransomware targeting butcher shops"],
    answer: 1
  },
  {
    id: 191,
    category: "General",
    difficulty: "hard",
    question: "What is 'threat actor' categorization and how does it affect phishing defense strategy?",
    options: ["Actors in cybersecurity movies", "Classifying attackers by motivation and capability (nation-state, cybercriminal, hacktivist, insider) — each requires different defensive countermeasures", "A method for categorizing malware families", "A way to rank cybersecurity researchers"],
    answer: 1
  },
  {
    id: 192,
    category: "General",
    difficulty: "hard",
    question: "What is 'kill chain' analysis in phishing incident response?",
    options: ["Shutting down internet connections", "Analyzing the attacker's phishing attack lifecycle (recon → weaponize → deliver → exploit → install → C2 → exfiltrate) to identify where the attack can be disrupted", "A supply chain attack", "Terminating malware processes"],
    answer: 1
  },
  {
    id: 193,
    category: "General",
    difficulty: "hard",
    question: "What is 'MITRE ATT&CK' and how is it used in phishing defense?",
    options: ["An attack simulation game", "A knowledge base of adversary tactics and techniques based on real-world observations — used to map phishing TTPs and identify defensive gaps", "A penetration testing tool", "A government cybersecurity regulation"],
    answer: 1
  },
  {
    id: 194,
    category: "General",
    difficulty: "hard",
    question: "What does 'Indicators of Compromise' (IoC) mean in phishing investigation?",
    options: ["Signs that your antivirus is working", "Observable artifacts (malicious IPs, domains, email headers, file hashes) that indicate a system has been compromised by a phishing attack", "A legal compliance indicator", "A network performance metric"],
    answer: 1
  },
  {
    id: 195,
    category: "General",
    difficulty: "hard",
    question: "How does 'browser-in-the-browser' (BitB) attack work in phishing?",
    options: ["Running a browser inside a virtual machine", "Simulating a fake browser popup window within a webpage using HTML/CSS to mimic OAuth login popups, tricking users into entering credentials", "Hacking via browser extensions", "Injecting code into the browser's memory"],
    answer: 1
  },
  {
    id: 196,
    category: "General",
    difficulty: "hard",
    question: "What is 'PhaaS' (Phishing-as-a-Service) and why is it a significant threat?",
    options: ["A legitimate phishing awareness training platform", "A cybercriminal business model where ready-made phishing kits, infrastructure, and customer support are sold to non-technical attackers — dramatically lowering the barrier to launch sophisticated phishing campaigns", "A government anti-phishing service", "A PhD course on phishing"],
    answer: 1
  },
  {
    id: 197,
    category: "General",
    difficulty: "hard",
    question: "In forensic analysis of a phishing email, which element is most tamper-resistant and reliable for tracing origin?",
    options: ["The 'From' display name", "The full 'Received' header chain — each mail server stamps its own IP and timestamp, and while these can be partially faked, the receiving server's own stamp is authoritative", "The email subject line", "The Reply-To field"],
    answer: 1
  },
  {
    id: 198,
    category: "General",
    difficulty: "hard",
    question: "What is 'QR code phishing' (Quishing) and why does it evade traditional email security?",
    options: ["Phishing via QR code reader apps", "Embedding phishing URLs in QR codes within emails — traditional email security scans text URLs but often cannot decode and inspect QR code images for malicious links", "A physical QR code placed on objects", "Hacking via QR code scanners"],
    answer: 1
  },
  {
    id: 199,
    category: "General",
    difficulty: "hard",
    question: "What is 'MFA fatigue attack' (prompt bombing)?",
    options: ["When MFA apps run out of battery", "Sending repeated MFA push notifications to overwhelm and frustrate the victim until they accidentally approve or approve just to stop the notifications", "A brute force attack on MFA servers", "A technical exploit of the MFA protocol"],
    answer: 1
  },
  {
    id: 200,
    category: "General",
    difficulty: "hard",
    question: "What combination of technical controls provides the strongest defense against phishing in an organization?",
    options: ["Antivirus + firewall only", "Email authentication (SPF+DKIM+DMARC) + URL filtering + endpoint EDR + phishing-resistant MFA (FIDO2/hardware keys) + security awareness training — defense in depth", "Strong passwords + VPN only", "DNS filtering alone"],
    answer: 1
  }
];

// Summary:
// Easy: Q1–Q70 (70 questions)
// Medium: Q71–Q150 (80 questions)
// Hard: Q151–Q200 (50 questions)
// Categories: URL, Email, SMS, Social, General

window.PhishGuardQuestions = questions;
