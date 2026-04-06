// =============================================
// PHISHGUARD AI - CYBER DEFENSE DASHBOARD
// Professional JavaScript
// =============================================

// Global State
let currentUser = null;
let currentPlatform = 'whatsapp';
let analysisCount = 0;
let threatCount = 0;
let sessionStartTime = Date.now();

// QR Scanner
let qrScanner = null;

// Quiz State
let quizQuestions = [];
let quizIndex = 0;
let quizScore = 0;
let quizAnswered = false;

// Simulator State
let simScore = 0;
let simRound = 0;
let simStreak = 0;
let simScenarios = [];
let simTotalRounds = 10;

// Challenge State
let currentChallenge = null;
let challengeTimer = null;
let challengeStreak = parseInt(localStorage.getItem('challengeStreak') || '0');

// Charts
let threatPieChart = null;
let activityLineChart = null;

// Initialize App
document.addEventListener('DOMContentLoaded', async () => {
    initSidebar();
    initNavigation();
    initAuth();
    initLoginForm();
    initTheme();
    initUserMenu();
    initCharts();
    initAnalyzers();
    initQuiz();
    initSimulator();
    initChallenge();
    initProfile();
    initDateTime();
    initSessionTimer();
    initMusicPlayer();
    initNotifications();
    
    await checkAuth();
});

// =============================================
// SIDEBAR & NAVIGATION
// =============================================
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mobileBtn = document.getElementById('mobileMenuBtn');
    const sidebarToggle = document.getElementById('sidebarToggle');
    
    mobileBtn?.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });
    
    sidebarToggle?.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
    });
}

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            
            if (!page) return;
            
            // Update nav active state
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            // Show page
            showPage(page);
            
            // Close mobile sidebar
            document.getElementById('sidebar')?.classList.remove('open');
        });
    });
}

function showPage(pageName) {
    const pages = document.querySelectorAll('.page');
    pages.forEach(page => page.classList.remove('active'));
    
    const targetPage = document.getElementById(`page-${pageName}`);
    if (targetPage) {
        targetPage.classList.add('active');
        updatePageTitle(pageName);
    }
}

function updatePageTitle(pageName) {
    const titles = {
        dashboard: 'Dashboard',
        url: 'URL Checker',
        email: 'Email Analyzer',
        message: 'Message Scanner',
        qr: 'QR Scanner',
        simulator: 'Phishing Simulator',
        challenge: 'Daily Challenge',
        quiz: 'Cyber Quiz',
        videos: 'Educational Videos',
        history: 'Analysis History',
        profile: 'My Profile'
    };
    
    document.getElementById('currentPageTitle').textContent = titles[pageName] || 'Dashboard';
}

// =============================================
// AUTHENTICATION
// =============================================
function initAuth() {
    const overlay = document.getElementById('loginOverlay');
    
    // Show login screen initially
    overlay.style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';
}

function initLoginForm() {
    // Tab switching
    const tabs = document.querySelectorAll('.login-tab');
    const forms = document.querySelectorAll('.auth-form');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const formType = tab.dataset.form;
            
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            forms.forEach(f => {
                f.classList.remove('active');
                if (f.id === `${formType}FormMain`) {
                    f.classList.add('active');
                }
            });
        });
    });
    
    // Switch form links
    document.querySelectorAll('.switch-form').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const formType = link.dataset.form;
            document.querySelector(`.login-tab[data-form="${formType}"]`).click();
        });
    });
    
    // Password toggle
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.parentElement.querySelector('input');
            const icon = btn.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });
    });
    
    // Login form
    document.getElementById('loginFormMain')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('mainLoginEmail').value;
        const password = document.getElementById('mainLoginPassword').value;
        
        try {
            const res = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: email, password })
            });
            const data = await res.json();
            
            if (data.success) {
                currentUser = data.user;
                hideLoginScreen();
                updateUserUI();
                loadDashboardData();
                showToast('Welcome back, ' + currentUser.username + '!', 'success');
            } else {
                showError(data.error);
            }
        } catch (err) {
            showError('Login failed. Please try again.');
        }
    });
    
    // Register form
    document.getElementById('registerFormMain')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('mainRegName').value;
        const email = document.getElementById('mainRegEmail').value;
        const password = document.getElementById('mainRegPassword').value;
        const institution = document.getElementById('mainRegInstitution').value;
        
        try {
            const res = await fetch('/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: email.split('@')[0],
                    email, 
                    password, 
                    full_name: name,
                    institution 
                })
            });
            const data = await res.json();
            
            if (data.success) {
                showToast('Registration successful! Please login.', 'success');
                document.getElementById('mainLoginEmail').value = email;
                document.getElementById('loginFormMain').classList.add('active');
                document.getElementById('registerFormMain').classList.remove('active');
                document.querySelectorAll('.login-tab').forEach(t => {
                    t.classList.toggle('active', t.dataset.form === 'login');
                });
            } else {
                showError(data.error);
            }
        } catch (err) {
            showError('Registration failed. Please try again.');
        }
    });
    
    // Logout
    document.getElementById('logoutBtn')?.addEventListener('click', async (e) => {
        e.preventDefault();
        console.log('[DEBUG] Logging out user...');
        try {
            await fetch('/auth/logout', { method: 'POST' });
            currentUser = null;
            localStorage.removeItem('phishguard_user');
            localStorage.removeItem('phishguard_email');
            console.log('[DEBUG] Session cleared, redirecting to login...');
            window.location.href = '/login';
        } catch (err) {
            console.error('[ERROR] Logout failed:', err);
            showToast('Logout failed', 'error');
        }
    });
}

function showError(message) {
    const errorEl = document.getElementById('loginErrorMain');
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.classList.add('show');
        setTimeout(() => errorEl.classList.remove('show'), 3000);
    }
}

async function checkAuth() {
    try {
        const res = await fetch('/auth/check');
        const data = await res.json();
        
        if (data.logged_in) {
            currentUser = data.user;
            hideLoginScreen();
            updateUserUI();
            loadDashboardData();
        }
    } catch (err) {
        console.error('Auth check failed:', err);
    }
}

function hideLoginScreen() {
    const overlay = document.getElementById('loginOverlay');
    const container = document.getElementById('appContainer');
    
    if (overlay) overlay.style.display = 'none';
    if (container) container.style.display = 'flex';
}

function showLoginScreen() {
    const overlay = document.getElementById('loginOverlay');
    const container = document.getElementById('appContainer');
    
    if (overlay) overlay.style.display = 'flex';
    if (container) container.style.display = 'none';
    
    // Reset forms
    document.getElementById('loginFormMain')?.reset();
    document.getElementById('registerFormMain')?.reset();
}

function updateUserUI() {
    if (!currentUser) return;
    
    const userName = currentUser.username || currentUser.full_name || 'User';
    
    // Header
    document.getElementById('headerUserName').textContent = userName;
    document.getElementById('welcomeUserName').textContent = userName;
    
    // Load saved avatar from localStorage
    const savedAvatar = localStorage.getItem('phishguard_avatar');
    if (savedAvatar) {
        const headerImg = document.getElementById('userAvatarImg');
        const headerIcon = document.getElementById('userAvatarIcon');
        if (headerImg) {
            headerImg.src = savedAvatar;
            headerImg.style.display = 'block';
            if (headerIcon) headerIcon.style.display = 'none';
        }
    }
    
    // Profile
    document.getElementById('profileUserName').textContent = currentUser.full_name || userName;
    document.getElementById('profileUserEmail').textContent = currentUser.email;
    document.getElementById('profileUserInstitution').innerHTML = `<i class="fas fa-graduation-cap"></i> ${currentUser.institution || 'Not specified'}`;
    
    if (currentUser.created_at) {
        const isoStr = currentUser.created_at.replace(' ', 'T');
        const year = new Date(isoStr).getFullYear();
        document.getElementById('profileMemberSince').textContent = year;
    }
    
    // Load user stats
    loadUserStats();
}

async function loadUserStats() {
    try {
        const res = await fetch('/api/user/dashboard');
        const data = await res.json();
        
        if (data.stats) {
            document.getElementById('profileTotalScans').textContent = data.stats.total_analyses || 0;
            document.getElementById('profileThreatsFound').textContent = data.stats.phishing_detected || 0;
            document.getElementById('profileBadges').textContent = data.stats.badges_earned || 0;
            document.getElementById('profileQuizScore').textContent = data.stats.quiz_avg_score || 0;
        }
    } catch (err) {
        console.error('Failed to load user stats:', err);
    }
}

// =============================================
// THEME & UI
// =============================================
function initTheme() {
    const themeBtn = document.getElementById('themeBtn');
    const savedTheme = localStorage.getItem('phishguard_theme') || 'dark';
    
    // Apply saved theme
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        if (themeBtn) {
            const icon = themeBtn.querySelector('i');
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        }
    }
    
    themeBtn?.addEventListener('click', () => {
        const isLight = document.body.classList.toggle('light-theme');
        const icon = themeBtn.querySelector('i');
        
        if (isLight) {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
            localStorage.setItem('phishguard_theme', 'light');
        } else {
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
            localStorage.setItem('phishguard_theme', 'dark');
        }
    });
}

function initMusicPlayer() {
    const musicBtn = document.getElementById('musicBtn');
    if (!musicBtn) return;
    
    let isPlaying = false;
    let audio = null;
    
    musicBtn.addEventListener('click', () => {
        if (!audio) {
            audio = new Audio('static/assets/background-music.mp3');
            audio.loop = true;
        }
        
        if (isPlaying) {
            audio.pause();
            musicBtn.querySelector('i').classList.remove('fa-pause');
            musicBtn.querySelector('i').classList.add('fa-music');
            isPlaying = false;
        } else {
            audio.play().then(() => {
                musicBtn.querySelector('i').classList.remove('fa-music');
                musicBtn.querySelector('i').classList.add('fa-pause');
                isPlaying = true;
            }).catch(err => {
                showToast('Audio file not found', 'error');
            });
        }
    });
}

function initUserMenu() {
    const userMenu = document.getElementById('userMenuBtn');
    userMenu?.addEventListener('click', () => {
        userMenu.classList.toggle('active');
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!userMenu.contains(e.target)) {
            userMenu.classList.remove('active');
        }
    });
    
    // Logout button handler
    const logoutBtn = document.getElementById('logoutBtn');
    logoutBtn?.addEventListener('click', async (e) => {
        e.preventDefault();
        console.log('[DEBUG] Logging out user...');
        try {
            await fetch('/auth/logout', { method: 'POST' });
            currentUser = null;
            localStorage.removeItem('phishguard_user');
            localStorage.removeItem('phishguard_email');
            // Keep avatar - it should persist across logins!
            console.log('[DEBUG] Session cleared, redirecting to login...');
            window.location.href = '/login';
        } catch (err) {
            console.error('[ERROR] Logout failed:', err);
            showToast('Logout failed', 'error');
        }
    });
}

function initDateTime() {
    const dateEl = document.getElementById('currentDate');
    if (dateEl) {
        const updateDate = () => {
            const now = new Date();
            dateEl.textContent = now.toLocaleDateString('en-US', { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
        };
        updateDate();
        setInterval(updateDate, 60000);
    }
}

function initSessionTimer() {
    const timerEl = document.getElementById('sessionTime');
    if (timerEl) {
        setInterval(() => {
            const elapsed = Date.now() - sessionStartTime;
            const hours = Math.floor(elapsed / 3600000);
            const mins = Math.floor((elapsed % 3600000) / 60000);
            const secs = Math.floor((elapsed % 60000) / 1000);
            timerEl.textContent = `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }, 1000);
    }
}

function initNotifications() {
    const exportBtn = document.getElementById('exportHistoryBtn');
    exportBtn?.addEventListener('click', exportHistoryToPDF);
    
    const notifBtn = document.getElementById('notificationsBtn');
    notifBtn?.addEventListener('click', () => {
        showToast('Notifications feature coming soon!', 'info');
    });
}

async function exportHistoryToPDF() {
    showToast('Generating PDF...', 'info');
    
    try {
        const res = await fetch('/api/export/history');
        const contentType = res.headers.get('content-type');
        
        if (res.ok && contentType && contentType.includes('application/pdf')) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `phishguard_history_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showToast('PDF downloaded successfully!', 'success');
        } else {
            const text = await res.text();
            showToast('Failed to export PDF: ' + (text.substring(0, 50) || 'Server error'), 'error');
        }
    } catch (err) {
        showToast('Export failed: ' + err.message, 'error');
    }
}

// =============================================
 // CHARTS
 // =============================================
function initCharts() {
    initThreatPieChart();
    initActivityLineChart();
}

function initThreatPieChart() {
    const ctx = document.getElementById('threatPieChart');
    if (!ctx) return;
    
    threatPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['URL Phishing', 'Email Phishing', 'SMS Phishing', 'Social Scams'],
            datasets: [{
                data: [35, 25, 20, 20],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#8b5cf6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', padding: 15, font: { size: 11 } }
                }
            }
        }
    });
}

function initActivityLineChart() {
    const ctx = document.getElementById('activityLineChart');
    if (!ctx) return;
    
    const hours = [];
    const data = [];
    for (let i = 23; i >= 0; i--) {
        hours.push(i + ':00');
        data.push(Math.floor(Math.random() * 50) + 10);
    }
    
    activityLineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: hours,
            datasets: [{
                label: 'Scans',
                data: data,
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { 
                    beginAtZero: true, 
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#64748b' }
                },
                x: { 
                    grid: { display: false },
                    ticks: { color: '#64748b', maxTicksLimit: 8 }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function loadDashboardData() {
    loadStats();
    loadRecentActivity();
}

async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('statTotalScans').textContent = data.total_scans || 0;
        document.getElementById('statThreats').textContent = data.phishing_detected || 0;
        document.getElementById('statSafe').textContent = data.safe_detected || 0;
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

async function loadRecentActivity() {
    const tbody = document.getElementById('recentActivityTable');
    if (!tbody) return;
    
    try {
        const res = await fetch('/api/history?limit=5');
        const data = await res.json();
        
        if (data.length > 0) {
            tbody.innerHTML = data.map(item => `
                <tr>
                    <td><span class="history-type"><i class="fas ${getTypeIcon(item.analysis_type)}"></i></span></td>
                    <td>${escapeHtml(item.content || '').substring(0, 50)}...</td>
                    <td><span class="history-result ${item.prediction}">${item.prediction}</span></td>
                    <td>${Math.round(item.confidence * 100)}%</td>
                    <td class="history-time">${formatTime(item.created_at)}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        console.error('Failed to load activity:', err);
    }
}

function getTypeIcon(type) {
    const icons = { URL: 'fa-link', Email: 'fa-envelope', Message: 'fa-comment' };
    return icons[type] || 'fa-search';
}

function formatTime(dateStr) {
    if (!dateStr) return '';
    // Fix date parsing by converting space to T for ISO format
    const isoStr = dateStr.replace(' ', 'T');
    const date = new Date(isoStr);
    // Check if date is valid
    if (isNaN(date.getTime())) return dateStr;
    return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =============================================
// ANALYZERS
// =============================================
function initAnalyzers() {
    // URL Analyzer
    document.getElementById('analyzeUrlBtn')?.addEventListener('click', analyzeURL);
    document.getElementById('urlInput')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeURL();
    });
    
    // Email Analyzer
    document.getElementById('analyzeEmailBtn')?.addEventListener('click', analyzeEmail);
    
    // Message Analyzer
    document.getElementById('analyzeMessageBtn')?.addEventListener('click', analyzeMessage);
    
    // History page
    initHistoryPage();
    
    // Platform selector
    document.querySelectorAll('.platform-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.platform-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentPlatform = btn.dataset.platform;
        });
    });
    
    // Demo buttons
    document.querySelectorAll('.demo-btn.danger, .demo-btn.safe').forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.dataset.url;
            const email = btn.dataset.email;
            
            if (url) {
                document.getElementById('urlInput').value = url;
                analyzeURL();
            }
            if (email) {
                document.getElementById('emailInput').value = email;
                analyzeEmail();
            }
        });
    });
    
    // QR Scanner
    initQRScanner();
}

async function analyzeURL() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) { showToast('Please enter a URL', 'error'); return; }
    
    showLoading();
    
    try {
        const res = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        hideLoading();
        
        if (data.success) {
            displayAnalyzerResult('urlResult', data);
            analysisCount++;
            if (data.prediction === 'phishing') threatCount++;
            updateDashboardStats();
            saveAnalysisToDB('URL', url, data);
        } else {
            showToast(data.error, 'error');
        }
    } catch (err) {
        hideLoading();
        showToast('Analysis failed', 'error');
    }
}

async function analyzeEmail() {
    const email = document.getElementById('emailInput').value.trim();
    if (!email) { showToast('Please enter email content', 'error'); return; }
    
    showLoading();
    
    try {
        const res = await fetch('/api/analyze/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        hideLoading();
        
        if (data.success) {
            displayAnalyzerResult('emailResult', data);
            analysisCount++;
            if (data.prediction === 'phishing') threatCount++;
            updateDashboardStats();
            saveAnalysisToDB('Email', email, data);
        } else {
            showToast(data.error, 'error');
        }
    } catch (err) {
        hideLoading();
        showToast('Analysis failed', 'error');
    }
}

async function analyzeMessage() {
    const message = document.getElementById('messageInput').value.trim();
    if (!message) { showToast('Please enter message content', 'error'); return; }
    
    showLoading();
    
    try {
        const res = await fetch('/api/analyze/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, platform: currentPlatform })
        });
        const data = await res.json();
        hideLoading();
        
        if (data.success) {
            displayAnalyzerResult('messageResult', data);
            analysisCount++;
            if (data.prediction === 'phishing') threatCount++;
            updateDashboardStats();
            saveAnalysisToDB('Message', message, data);
        } else {
            showToast(data.error, 'error');
        }
    } catch (err) {
        hideLoading();
        showToast('Analysis failed', 'error');
    }
}

// Global variable to store current analysis data for PDF download
let currentAnalysisData = null;

function displayAnalyzerResult(elementId, data) {
    const container = document.getElementById(elementId);
    if (!container) return;
    
    currentAnalysisData = data;
    
    const riskScore = data.risk_score || 0;
    const prediction = data.prediction || data.prediction;
    const riskLevel = data.risk_level || prediction;
    
    // Color based on risk score
    let riskColor = '#10b981'; // Safe - green
    if (riskScore >= 61) riskColor = '#ef4444'; // Phishing - red
    else if (riskScore >= 31) riskColor = '#f59e0b'; // Suspicious - orange
    
    // Get explanation text
    const explanations = data.explanations || data.reasons || [];
    const recommendation = data.recommendation || '';
    
    container.innerHTML = `
        <div class="result-header">
            <div class="risk-score-display">
                <span class="risk-number" style="color: ${riskColor}">${riskScore}</span>
                <span class="risk-label">Risk Score</span>
            </div>
            <h3 style="color: ${riskColor}">${riskLevel}</h3>
        </div>
        
        <div class="result-meters">
            <div class="meter-container">
                <div class="meter-label">Phishing Probability</div>
                <div class="meter-bar">
                    <div class="meter-fill" style="width: ${riskScore}%; background: ${riskColor}"></div>
                </div>
                <span class="meter-value">${riskScore}%</span>
            </div>
        </div>
        
        ${explanations.length ? `
            <div class="explanation-section">
                <h4><i class="fas fa-info-circle"></i> Why this result?</h4>
                <ul class="result-reasons">
                    ${explanations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </div>
        ` : ''}
        
        ${recommendation ? `
            <div class="recommendation-box" style="border-left: 3px solid ${riskColor};">
                <strong>Recommendation:</strong> ${recommendation}
            </div>
        ` : ''}
        
        <div class="result-actions">
            <button class="btn-neon secondary" onclick="downloadCurrentAnalysisPDF()">
                <i class="fas fa-download"></i> Download Report
            </button>
        </div>
    `;
    
    container.className = `analyzer-result`;
    container.style.display = 'block';
}

async function downloadCurrentAnalysisPDF() {
    if (!currentAnalysisData) {
        showToast('No analysis data available', 'error');
        return;
    }
    await downloadAnalysisPDF(currentAnalysisData);
}

async function downloadAnalysisPDF(data) {
    console.log('[DEBUG] downloadAnalysisPDF called with:', data);
    showToast('Generating PDF report...', 'info');
    
    try {
        const requestBody = {
            prediction: data.prediction,
            confidence: data.confidence,
            confidence_percent: data.confidence_percent,
            reasons: data.reasons,
            features: data.features,
            type: data.type || 'URL',
            content: data.content || data.url || data.message || '',
            analyzed_at: data.analyzed_at || new Date().toISOString()
        };
        console.log('[DEBUG] Sending request to /api/export/pdf:', requestBody);
        
        const res = await fetch('/api/export/pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        console.log('[DEBUG] Response status:', res.status);
        console.log('[DEBUG] Response headers:', res.headers.get('content-type'));
        
        if (res.status === 401) {
            showToast('Please login to download PDF', 'error');
            window.location.href = '/login';
            return;
        }
        
        const contentType = res.headers.get('content-type');
        
        if (res.ok && contentType && contentType.includes('application/pdf')) {
            const blob = await res.blob();
            console.log('[DEBUG] PDF blob size:', blob.size);
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `phishguard_report_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showToast('PDF downloaded successfully!', 'success');
        } else {
            const errorText = await res.text();
            console.error('[ERROR] PDF generation failed:', errorText);
            showToast('Failed to generate PDF: ' + (errorText.substring(0, 100) || 'Unknown error'), 'error');
        }
    } catch (err) {
        console.error('[ERROR] Download exception:', err);
        showToast('Export failed: ' + err.message, 'error');
    }
}

function updateDashboardStats() {
    document.getElementById('statTotalScans').textContent = analysisCount;
    document.getElementById('statThreats').textContent = threatCount;
    document.getElementById('statSafe').textContent = analysisCount - threatCount;
}

async function initHistoryPage() {
    loadHistory();
    
    document.getElementById('historyFilterType')?.addEventListener('change', loadHistory);
    document.getElementById('historyFilterResult')?.addEventListener('change', loadHistory);
}

async function loadHistory() {
    const container = document.getElementById('historyList');
    if (!container) return;
    
    try {
        const typeFilter = document.getElementById('historyFilterType')?.value || '';
        const resultFilter = document.getElementById('historyFilterResult')?.value || '';
        
        let url = '/api/user/analyses?limit=500';
        if (typeFilter) url += `&type=${typeFilter}`;
        
        const res = await fetch(url);
        let analyses = await res.json();
        
        if (resultFilter) {
            analyses = analyses.filter(a => a.prediction === resultFilter);
        }
        
        if (analyses.length > 0) {
            container.innerHTML = analyses.map(item => `
                <div class="history-item">
                    <div class="history-item-icon">
                        <i class="fas ${getTypeIcon(item.analysis_type)}"></i>
                    </div>
                    <div class="history-item-content">
                        <p class="history-item-text" title="${escapeHtml(item.content || '')}">${escapeHtml(item.content || '').substring(0, 80)}${(item.content || '').length > 80 ? '...' : ''}</p>
                        <span class="history-item-time">${formatTime(item.created_at)}</span>
                    </div>
                    <div class="history-item-result">
                        <span class="history-result ${item.prediction}">${item.prediction}</span>
                        <span class="history-confidence">${Math.round((item.confidence || 0) * 100)}%</span>
                    </div>
                    <div class="history-item-actions">
                        <button class="btn-icon" onclick="viewAnalysis(${item.id})" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn-icon" onclick="downloadSingleAnalysis(${item.id})" title="Download PDF">
                            <i class="fas fa-download"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>No analysis history yet.</p>
                </div>
            `;
        }
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

async function downloadSingleAnalysis(id) {
    console.log('[DEBUG] Downloading analysis ID:', id);
    showToast('Generating PDF...', 'info');
    
    try {
        const res = await fetch('/api/export/pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analysis_id: parseInt(id) })
        });
        
        console.log('[DEBUG] Response status:', res.status);
        
        if (res.status === 401) {
            showToast('Please login to download PDF', 'error');
            window.location.href = '/login';
            return;
        }
        
        const contentType = res.headers.get('content-type');
        
        if (res.ok && contentType && contentType.includes('application/pdf')) {
            const blob = await res.blob();
            console.log('[DEBUG] PDF blob size:', blob.size);
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `phishguard_report_${id}_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showToast('PDF downloaded!', 'success');
        } else {
            const errorText = await res.text();
            console.error('[ERROR] PDF download failed:', errorText);
            showToast('Failed to download PDF', 'error');
        }
    } catch (err) {
        console.error('[ERROR] Download exception:', err);
        showToast('Export failed: ' + err.message, 'error');
    }
}

async function viewAnalysis(id) {
    showToast('Loading analysis...', 'info');
    
    try {
        const res = await fetch(`/api/analysis/${id}`);
        
        if (res.status === 401) {
            showToast('Please login to view analysis', 'error');
            window.location.href = '/login';
            return;
        }
        
        if (!res.ok) {
            throw new Error('Failed to load analysis');
        }
        
        const data = await res.json();
        showAnalysisModal(data);
        
    } catch (err) {
        console.error('[ERROR] View analysis failed:', err);
        showToast('Failed to load analysis details', 'error');
    }
}

function showAnalysisModal(data) {
    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    const features = data.features || {};
    
    const featuresHtml = Object.keys(features).length > 0 
        ? Object.entries(features).map(([key, value]) => `
            <div class="feature-item">
                <span class="feature-key">${escapeHtml(key)}:</span>
                <span class="feature-value">${escapeHtml(String(value))}</span>
            </div>
        `).join('')
        : '<p class="no-data">No feature data available</p>';
    
    const reasonsHtml = reasons.length > 0
        ? reasons.map(r => `<li>${escapeHtml(String(r))}</li>`).join('')
        : '<p class="no-data">No specific reasons recorded</p>';
    
    const modalContent = `
        <div class="analysis-detail-modal">
            <div class="modal-section">
                <h4><i class="fas fa-link"></i> Content / URL</h4>
                <div class="detail-content">
                    <a href="${escapeHtml(data.content || '')}" target="_blank" class="url-link">${escapeHtml(data.content || 'N/A')}</a>
                </div>
            </div>
            
            <div class="modal-section">
                <h4><i class="fas fa-calendar"></i> Analyzed On</h4>
                <div class="detail-content">${formatTime(data.created_at)}</div>
            </div>
            
            <div class="modal-section">
                <h4><i class="fas fa-shield-alt"></i> Prediction Result</h4>
                <div class="detail-content">
                    <span class="result-badge ${data.prediction}">${escapeHtml(data.prediction || 'Unknown').toUpperCase()}</span>
                    <span class="confidence-badge">${Math.round((data.confidence || 0) * 100)}% Confidence</span>
                </div>
            </div>
            
            <div class="modal-section">
                <h4><i class="fas fa-list-check"></i> Detection Reasons</h4>
                <div class="detail-content">
                    <ul class="reasons-list">${reasonsHtml}</ul>
                </div>
            </div>
            
            <div class="modal-section">
                <h4><i class="fas fa-code"></i> Analysis Features</h4>
                <div class="detail-content features-grid">${featuresHtml}</div>
            </div>
            
            <div class="modal-actions">
                <button class="btn-neon secondary" onclick="downloadSingleAnalysis(${data.id})">
                    <i class="fas fa-download"></i> Download PDF
                </button>
                <button class="btn-neon" onclick="closeModal()">
                    <i class="fas fa-times"></i> Close
                </button>
            </div>
        </div>
    `;
    
    showModal('Analysis Details', modalContent);
}

function showModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'analysisModal';
    modal.innerHTML = `
        <div class="modal-container">
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="modal-close" onclick="closeModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                ${content}
            </div>
        </div>
    `;
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });
    
    document.body.appendChild(modal);
    setTimeout(() => modal.classList.add('active'), 10);
}

function closeModal() {
    const modal = document.getElementById('analysisModal');
    if (modal) {
        modal.classList.remove('active');
        setTimeout(() => modal.remove(), 300);
    }
}

async function saveAnalysisToDB(type, content, data) {
    if (!currentUser) return;
    
    try {
        await fetch('/api/user/save-analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: type,
                content: content,
                prediction: data.prediction,
                confidence: data.confidence,
                reasons: data.reasons,
                features: data.features
            })
        });
    } catch (err) {
        console.error('Failed to save analysis to database:', err);
    }
}

// =============================================
 // QR SCANNER
 // =============================================
function initQRScanner() {
    document.getElementById('startCameraBtn')?.addEventListener('click', startQRCamera);
    document.getElementById('stopCameraBtn')?.addEventListener('click', stopQRCamera);
    
    document.getElementById('qrImageInput')?.addEventListener('change', (e) => {
        if (e.target.files[0]) {
            processQRImage(e.target.files[0]);
        }
    });
}

async function startQRCamera() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        const video = document.getElementById('qrVideo');
        const container = document.getElementById('qrVideoContainer');
        const placeholder = document.getElementById('qrPlaceholder');
        
        video.srcObject = stream;
        container.style.display = 'block';
        placeholder.style.display = 'none';
        
        document.getElementById('startCameraBtn').style.display = 'none';
        document.getElementById('stopCameraBtn').style.display = 'inline-flex';
        
        qrScanner = setInterval(scanQRFrame, 100);
    } catch (err) {
        showToast('Camera access denied', 'error');
    }
}

function stopQRCamera() {
    if (qrScanner) {
        clearInterval(qrScanner);
        qrScanner = null;
    }
    
    const video = document.getElementById('qrVideo');
    if (video.srcObject) {
        video.srcObject.getTracks().forEach(track => track.stop());
    }
    
    document.getElementById('qrVideoContainer').style.display = 'none';
    document.getElementById('qrPlaceholder').style.display = 'flex';
    document.getElementById('startCameraBtn').style.display = 'inline-flex';
    document.getElementById('stopCameraBtn').style.display = 'none';
}

function scanQRFrame() {
    const video = document.getElementById('qrVideo');
    const canvas = document.getElementById('qrCanvas');
    const ctx = canvas.getContext('2d');
    
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        
        // Note: In production, use a QR library like jsQR
        // For demo, we'll simulate detection
    }
}

function processQRImage(file) {
    showToast('QR Scanner feature coming soon!', 'info');
    // Note: QR code scanning requires additional libraries (jsQR)
    // For now, use the camera feature or enter URL manually
}

// =============================================
// QUIZ
// =============================================
function initQuiz() {
    document.getElementById('startQuizBtn')?.addEventListener('click', startQuiz);
    document.getElementById('nextQuestionBtn')?.addEventListener('click', nextQuestion);
    document.getElementById('skipQuestionBtn')?.addEventListener('click', nextQuestion);
}

async function startQuiz() {
    const category = document.getElementById('quizCategory').value;
    const difficulty = document.getElementById('quizDifficulty').value;
    
    try {
        let url = '/api/quiz?limit=5';
        if (category) url += `&category=${category}`;
        if (difficulty) url += `&difficulty=${difficulty}`;
        
        const res = await fetch(url);
        const data = await res.json();
        
        if (data.questions?.length > 0) {
            quizQuestions = data.questions;
            quizIndex = 0;
            quizScore = 0;
            showQuizCard();
            displayQuestion();
        } else {
            showToast('No questions available', 'error');
        }
    } catch (err) {
        showToast('Failed to load quiz', 'error');
    }
}

function showQuizCard() {
    document.getElementById('quizCard').style.display = 'block';
    document.getElementById('startQuizBtn').style.display = 'none';
}

function displayQuestion() {
    if (quizIndex >= quizQuestions.length) {
        showQuizResults();
        return;
    }
    
    const q = quizQuestions[quizIndex];
    quizAnswered = false;
    
    document.getElementById('quizProgress').textContent = `Question ${quizIndex + 1}/${quizQuestions.length}`;
    document.getElementById('quizProgressFill').style.width = `${((quizIndex + 1) / quizQuestions.length) * 100}%`;
    document.getElementById('quizQuestion').textContent = q.question;
    
    const optionsContainer = document.getElementById('quizOptions');
    const options = [
        { key: 'A', value: q.option_a },
        { key: 'B', value: q.option_b },
        { key: 'C', value: q.option_c },
        { key: 'D', value: q.option_d }
    ];
    
    optionsContainer.innerHTML = options.filter(o => o.value).map(o => `
        <div class="quiz-option" data-answer="${o.key}">
            <span class="option-letter">${o.key}</span>
            <span>${o.value}</span>
        </div>
    `).join('');
    
    optionsContainer.querySelectorAll('.quiz-option').forEach(opt => {
        opt.addEventListener('click', () => selectQuizAnswer(opt, q));
    });
    
    document.getElementById('nextQuestionBtn').disabled = true;
}

function selectQuizAnswer(element, question) {
    if (quizAnswered) return;
    quizAnswered = true;
    
    const selected = element.dataset.answer;
    const isCorrect = selected === question.correct_answer;
    
    if (isCorrect) quizScore++;
    
    element.classList.add(isCorrect ? 'correct' : 'incorrect');
    
    // Highlight correct answer
    const options = document.querySelectorAll('.quiz-option');
    options.forEach(opt => {
        if (opt.dataset.answer === question.correct_answer) {
            opt.classList.add('correct');
        }
    });
    
    document.getElementById('nextQuestionBtn').disabled = false;
}

function nextQuestion() {
    quizIndex++;
    displayQuestion();
}

function showQuizResults() {
    document.getElementById('quizCard').style.display = 'none';
    const results = document.getElementById('quizResults');
    results.style.display = 'block';
    
    const percentage = Math.round((quizScore / quizQuestions.length) * 100);
    let grade = '';
    if (percentage >= 90) grade = 'Excellent!';
    else if (percentage >= 70) grade = 'Good Job!';
    else if (percentage >= 50) grade = 'Keep Learning!';
    else grade = 'Try Again!';
    
    results.innerHTML = `
        <h3>Quiz Complete!</h3>
        <p style="font-size: 3rem; color: var(--primary); margin: 20px 0;">${quizScore}/${quizQuestions.length}</p>
        <p style="font-size: 1.5rem; margin-bottom: 20px;">${grade}</p>
        <button class="btn-neon" onclick="location.reload()">
            <i class="fas fa-redo"></i> Try Again
        </button>
    `;
}

// =============================================
// SIMULATOR
// =============================================
const simulatorData = [
    { sender: "security@paypa1-account.tk", body: "URGENT: Your PayPal account has been limited. Verify your identity immediately: http://paypa1-secure.tk/verify", isPhishing: true },
    { sender: "noreply@amazon.in", body: "Your order has been confirmed and will be shipped within 2 business days. Order: Sony Headphones - Rs. 4,999. Expected delivery: 3-5 days.", isPhishing: false },
    { sender: "+91-9876543210", body: "Dear Customer, Your SBI account has been BLOCKED. Call immediately: 9876543210 to unlock. Avoid permanent suspension.", isPhishing: true },
    { sender: "friend@college.edu", body: "Hey! Attaching the project files. Let me know if you need anything else. Cheers!", isPhishing: false },
    { sender: "winner@lottery-intl.org", body: "CONGRATULATIONS!!! You have won $1,000,000 in our International Lottery! Reply within 48 hours to claim!", isPhishing: true }
];

function initSimulator() {
    document.getElementById('startSimBtn')?.addEventListener('click', startSimulator);
    document.getElementById('simSafeBtn')?.addEventListener('click', () => submitSimAnswer(false));
    document.getElementById('simDangerBtn')?.addEventListener('click', () => submitSimAnswer(true));
}

function startSimulator() {
    simScore = 0;
    simRound = 0;
    simStreak = 0;
    simScenarios = [...simulatorData].sort(() => Math.random() - 0.5).slice(0, simTotalRounds);
    
    document.getElementById('startSimBtn').style.display = 'none';
    document.getElementById('simScenario').style.display = 'block';
    document.getElementById('simFeedback').style.display = 'none';
    
    loadNextScenario();
}

function loadNextScenario() {
    if (simRound >= simTotalRounds) {
        showSimResults();
        return;
    }
    
    const scenario = simScenarios[simRound];
    document.getElementById('simRound').textContent = `${simRound + 1}/${simTotalRounds}`;
    document.getElementById('simScore').textContent = simScore;
    document.getElementById('simStreak').textContent = simStreak;
    document.getElementById('simSender').textContent = scenario.sender;
    document.getElementById('simBody').innerHTML = scenario.body.replace(/\n/g, '<br>');
    
    document.getElementById('simSafeBtn').disabled = false;
    document.getElementById('simDangerBtn').disabled = false;
    document.getElementById('simFeedback').style.display = 'none';
}

function submitSimAnswer(guessedPhishing) {
    const scenario = simScenarios[simRound];
    const correct = guessedPhishing === scenario.isPhishing;
    
    document.getElementById('simSafeBtn').disabled = true;
    document.getElementById('simDangerBtn').disabled = true;
    
    const feedback = document.getElementById('simFeedback');
    feedback.style.display = 'block';
    feedback.className = `sim-feedback ${correct ? 'correct' : 'incorrect'}`;
    
    if (correct) {
        simScore += 100 + (simStreak * 10);
        simStreak++;
        feedback.innerHTML = `<h4><i class="fas fa-check-circle"></i> Correct!</h4><p>+${100 + (simStreak * 10)} points!</p>`;
    } else {
        simStreak = 0;
        feedback.innerHTML = `<h4><i class="fas fa-times-circle"></i> Incorrect</h4><p>This was ${scenario.isPhishing ? 'PHISHING' : 'LEGITIMATE'}</p>`;
    }
    
    simRound++;
    document.getElementById('simScore').textContent = simScore;
    
    setTimeout(loadNextScenario, 2000);
}

function showSimResults() {
    document.getElementById('simScenario').style.display = 'none';
    document.getElementById('simFeedback').style.display = 'none';
    
    const results = document.getElementById('simResults');
    results.style.display = 'block';
    results.innerHTML = `
        <h3>Simulator Complete!</h3>
        <p style="font-size: 2rem; color: var(--primary); margin: 20px 0;">Score: ${simScore}</p>
        <button class="btn-neon" onclick="startSimulator()">
            <i class="fas fa-redo"></i> Play Again
        </button>
    `;
    
    document.getElementById('startSimBtn').style.display = 'inline-flex';
    document.getElementById('startSimBtn').innerHTML = '<i class="fas fa-play"></i> Play Again';
}

// =============================================
// CHALLENGE
// =============================================
const challenges = [
    { title: "Spot the Suspicious URL", desc: "Which URL is most likely a phishing attempt?", options: ["https://www.google.com", "https://paypal.com.secure-login.tk/verify", "https://github.com/microsoft"], correct: 1 },
    { title: "Identify the Fake Email", desc: "Which sender address is from a scammer?", options: ["support@apple.com", "security@amazon.co.uk.scam-site.ru", "noreply@google.com"], correct: 1 },
    { title: "Detect SMiShing", desc: "Which SMS is a smishing attempt?", options: ["Your OTP is 123456. -Paytm", "URGENT: Your bank account HACKED! Call NOW!", "Meeting at 3 PM."], correct: 1 }
];

function initChallenge() {
    document.getElementById('challengeStreakText').textContent = `Streak: ${challengeStreak} days`;
    
    const today = new Date().toDateString();
    const savedChallenge = localStorage.getItem('dailyChallenge');
    
    if (savedChallenge) {
        currentChallenge = JSON.parse(savedChallenge);
    } else {
        const dayIndex = Math.floor((new Date() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
        currentChallenge = challenges[dayIndex % challenges.length];
        localStorage.setItem('dailyChallenge', JSON.stringify(currentChallenge));
    }
    
    displayChallenge();
    startChallengeTimer();
    
    document.getElementById('submitChallengeBtn')?.addEventListener('click', submitChallengeAnswer);
}

function displayChallenge() {
    if (!currentChallenge) return;
    
    document.getElementById('challengeTitle').textContent = currentChallenge.title;
    document.getElementById('challengeDesc').textContent = currentChallenge.desc;
    
    const optionsContainer = document.getElementById('challengeOptions');
    optionsContainer.innerHTML = currentChallenge.options.map((opt, i) => `
        <div class="challenge-option" data-index="${i}">
            <span class="option-letter">${String.fromCharCode(65 + i)}</span>
            <span>${opt}</span>
        </div>
    `).join('');
    
    optionsContainer.querySelectorAll('.challenge-option').forEach(opt => {
        opt.addEventListener('click', () => {
            optionsContainer.querySelectorAll('.challenge-option').forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
        });
    });
}

function startChallengeTimer() {
    const endTime = new Date();
    endTime.setHours(23, 59, 59, 999);
    
    if (challengeTimer) clearInterval(challengeTimer);
    
    challengeTimer = setInterval(() => {
        const now = new Date();
        const diff = endTime - now;
        
        if (diff <= 0) {
            document.getElementById('challengeTimer').textContent = '00:00:00';
            clearInterval(challengeTimer);
            return;
        }
        
        const hours = Math.floor(diff / 3600000);
        const mins = Math.floor((diff % 3600000) / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        
        document.getElementById('challengeTimer').textContent = 
            `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }, 1000);
}

function submitChallengeAnswer() {
    const selected = document.querySelector('.challenge-option.selected');
    if (!selected) { showToast('Please select an option', 'error'); return; }
    
    const index = parseInt(selected.dataset.index);
    const isCorrect = index === currentChallenge.correct;
    
    const result = document.getElementById('challengeResult');
    result.style.display = 'block';
    result.className = `challenge-result ${isCorrect ? 'correct' : 'incorrect'}`;
    
    if (isCorrect) {
        challengeStreak++;
        localStorage.setItem('challengeStreak', challengeStreak.toString());
        document.getElementById('challengeStreakText').textContent = `Streak: ${challengeStreak} days`;
        result.innerHTML = `<h4><i class="fas fa-check-circle"></i> Correct!</h4><p>+100 points!</p>`;
    } else {
        result.innerHTML = `<h4><i class="fas fa-times-circle"></i> Incorrect</h4><p>The correct answer was: ${String.fromCharCode(65 + currentChallenge.correct)}</p>`;
    }
    
    document.getElementById('submitChallengeBtn').style.display = 'none';
}

// =============================================
// PROFILE
// =============================================
function initProfile() {
    document.getElementById('uploadAvatarBtn')?.addEventListener('click', () => {
        document.getElementById('avatarUpload').click();
    });
    
    document.getElementById('avatarUpload')?.addEventListener('change', (e) => {
        if (e.target.files[0]) {
            uploadAvatar(e.target.files[0]);
        }
    });
    
    document.getElementById('profileSettingsForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        showToast('Settings saved!', 'success');
    });
    
    // Video cards click handler
    document.querySelectorAll('.video-card').forEach(card => {
        card.addEventListener('click', () => {
            const title = card.querySelector('h3').textContent;
            showToast('Video: ' + title + ' - Coming soon!', 'info');
        });
    });
}

function uploadAvatar(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const img = document.getElementById('profileAvatarImg');
        const icon = document.getElementById('profileAvatarIcon');
        
        img.src = e.target.result;
        img.style.display = 'block';
        icon.style.display = 'none';
        
        // Update header avatar too
        const headerImg = document.getElementById('userAvatarImg');
        const headerIcon = document.getElementById('userAvatarIcon');
        headerImg.src = e.target.result;
        headerImg.style.display = 'block';
        headerIcon.style.display = 'none';
        
        // Save avatar to localStorage (persistent across refreshes)
        localStorage.setItem('phishguard_avatar', e.target.result);
        
        showToast('Avatar updated!', 'success');
    };
    reader.readAsDataURL(file);
}

// =============================================
// UTILITIES
// =============================================
function showLoading() {
    document.getElementById('loadingOverlay')?.classList.add('show');
}

function hideLoading() {
    document.getElementById('loadingOverlay')?.classList.remove('show');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = { success: 'fa-check-circle', error: 'fa-times-circle', info: 'fa-info-circle' };
    toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${message}</span>`;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Make functions globally available
window.startQuiz = startQuiz;
window.startSimulator = startSimulator;
window.downloadSingleAnalysis = downloadSingleAnalysis;
window.downloadAnalysisPDF = downloadAnalysisPDF;
window.downloadCurrentAnalysisPDF = downloadCurrentAnalysisPDF;

// =============================================
// AI CHATBOT
// =============================================
let chatbotOpen = false;

function initChatbot() {
    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbotClose = document.getElementById('chatbotClose');
    const chatbotMinimize = document.getElementById('chatbotMinimize');
    const chatbotSend = document.getElementById('chatbotSend');
    const chatbotInput = document.getElementById('chatbotInput');
    
    if (!chatbotToggle) return;
    
    chatbotToggle.addEventListener('click', () => {
        chatbotOpen = true;
        document.getElementById('chatbotContainer').classList.add('active');
        document.getElementById('chatbotInput')?.focus();
    });
    
    chatbotClose?.addEventListener('click', closeChatbot);
    chatbotMinimize?.addEventListener('click', closeChatbot);
    
    chatbotSend?.addEventListener('click', sendChatMessage);
    
    chatbotInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendChatMessage();
    });
    
    // Add quick actions
    document.querySelectorAll('.chat-quick-action').forEach(btn => {
        btn.addEventListener('click', () => {
            document.getElementById('chatbotInput').value = btn.dataset.question;
            sendChatMessage();
        });
    });
}

function closeChatbot() {
    chatbotOpen = false;
    document.getElementById('chatbotContainer')?.classList.remove('active');
}

async function sendChatMessage() {
    const input = document.getElementById('chatbotInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    const messagesContainer = document.getElementById('chatbotMessages');
    
    // Add user message
    addChatMessage(message, 'user');
    input.value = '';
    
    // Show typing indicator
    const typingEl = document.createElement('div');
    typingEl.className = 'chat-message bot typing';
    typingEl.innerHTML = '<div class="typing-indicator"><span></span><span></span><span></span></div>';
    messagesContainer.appendChild(typingEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    try {
        // Check if user is logged in
        const user = JSON.parse(localStorage.getItem('phishguard_user') || '{}');
        if (!user.id) {
            typingEl.remove();
            addChatMessage("Please login to use the chatbot feature.", 'bot');
            return;
        }
        
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        const data = await response.json();
        
        // Remove typing indicator
        typingEl.remove();
        
        // Add bot response
        if (data.success) {
            addChatMessage(data.response, 'bot');
        } else {
            addChatMessage("Sorry, I couldn't understand that. Try asking about phishing or security tips!", 'bot');
        }
    } catch (error) {
        typingEl.remove();
        addChatMessage("I'm having trouble connecting. Please try again later.", 'bot');
    }
}

function addChatMessage(text, sender) {
    const messagesContainer = document.getElementById('chatbotMessages');
    const messageEl = document.createElement('div');
    messageEl.className = `chat-message ${sender}`;
    
    // Format markdown-like text
    let formattedText = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>')
        .replace(/🔹/g, '<span class="bullet">•</span>')
        .replace(/🔍/g, '<span class="emoji">🔍</span>')
        .replace(/🛡️/g, '<span class="emoji">🛡️</span>')
        .replace(/🔐/g, '<span class="emoji">🔐</span>')
        .replace(/🔴/g, '<span class="emoji">🔴</span>')
        .replace(/🦠/g, '<span class="emoji">🦠</span>')
        .replace(/⚠️/g, '<span class="emoji">⚠️</span>')
        .replace(/🎣/g, '<span class="emoji">🎣</span>')
        .replace(/📢/g, '<span class="emoji">📢</span>')
        .replace(/📊/g, '<span class="emoji">📊</span>')
        .replace(/1️⃣/g, '<span class="emoji">1️⃣</span>')
        .replace(/2️⃣/g, '<span class="emoji">2️⃣</span>')
        .replace(/3️⃣/g, '<span class="emoji">3️⃣</span>')
        .replace(/✅/g, '<span class="emoji">✅</span>')
        .replace(/❌/g, '<span class="emoji">❌</span>')
        .replace(/🚀/g, '<span class="emoji">🚀</span>')
        .replace(/👌/g, '<span class="emoji">👌</span>')
        .replace(/🦸/g, '<span class="emoji">🦸</span>')
        .replace(/🚩/g, '<span class="emoji">🚩</span>')
        .replace(/💡/g, '<span class="emoji">💡</span>');
    
    messageEl.innerHTML = formattedText;
    messagesContainer.appendChild(messageEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Initialize chatbot on load
document.addEventListener('DOMContentLoaded', initChatbot);

// Video Modal Functions
function openVideoModal(videoUrl) {
    const modal = document.getElementById('videoModal');
    const iframe = document.getElementById('videoFrame');
    
    if (modal && iframe) {
        iframe.src = videoUrl + '?autoplay=1';
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeVideoModal() {
    const modal = document.getElementById('videoModal');
    const iframe = document.getElementById('videoFrame');
    
    if (modal && iframe) {
        modal.classList.remove('active');
        iframe.src = '';
        document.body.style.overflow = '';
    }
}

// Close modal on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeVideoModal();
    }
});

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('videoModal');
    if (e.target === modal) {
        closeVideoModal();
    }
});
