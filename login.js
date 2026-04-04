// =============================================
// PHISHGUARD AI - LOGIN SYSTEM
// Auto-Login with Email OTP
// =============================================

document.addEventListener('DOMContentLoaded', () => {
    initLoginSystem();
});

function initLoginSystem() {
    // DOM Elements
    const screens = {
        autoLogin: document.getElementById('autoLoginScreen'),
        email: document.getElementById('emailScreen'),
        otp: document.getElementById('otpScreen'),
        register: document.getElementById('registerScreen'),
        success: document.getElementById('successScreen'),
        forgotPassword: document.getElementById('forgotPasswordScreen'),
        newPassword: document.getElementById('newPasswordScreen')
    };
    
    // State
    let currentScreen = 'autoLogin';
    let currentEmail = '';
    let timerInterval = null;
    let resetTimerInterval = null;
    let timerSeconds = 60;
    let resetTimerSeconds = 60;
    
    // Initialize
    checkAutoLogin();
    
    // Event Listeners
    setupEventListeners();
    
    // Auto-Login Check
    async function checkAutoLogin() {
        try {
            // First check localStorage
            const savedEmail = localStorage.getItem('phishguard_email');
            console.log('[DEBUG] Auto-login check - localStorage email:', savedEmail);
            
            // Then check session
            const response = await fetch('/api/auto-login-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            
            console.log('[DEBUG] Auto-login check - session response:', data);
            
            // Only show Continue if BOTH localStorage AND session have email
            if (data.success && data.found && data.email && savedEmail && savedEmail === data.email) {
                currentEmail = data.email;
                document.getElementById('savedEmail').textContent = currentEmail;
                showScreen('autoLogin');
            } else {
                // Clear any stale localStorage if session is cleared
                if (!data.found && savedEmail) {
                    localStorage.removeItem('phishguard_email');
                }
                showScreen('email');
            }
        } catch (error) {
            console.error('Auto-login check failed:', error);
            showScreen('email');
        }
    }
    
    // Screen Management
    function showScreen(screenName) {
        Object.values(screens).forEach(screen => screen.classList.remove('active'));
        screens[screenName].classList.add('active');
        currentScreen = screenName;
        
        // Clear error messages
        const errorEl = document.getElementById('otpError');
        if (errorEl) errorEl.classList.remove('show');
        
        // Reset OTP inputs
        if (screenName === 'otp') {
            setTimeout(() => {
                document.querySelectorAll('.otp-input').forEach(input => {
                    input.value = '';
                    input.classList.remove('filled', 'error');
                });
                document.querySelector('.otp-input').focus();
            }, 100);
        }
    }
    
    // Event Listeners Setup
    function setupEventListeners() {
        // Auto-Login Continue
        document.getElementById('continueBtn').addEventListener('click', async () => {
            try {
                showLoading(document.getElementById('continueBtn'), true);
                
                const response = await fetch('/api/send-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: currentEmail })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('otpEmail').textContent = currentEmail;
                    startOtpTimer();
                    showScreen('otp');
                } else {
                    showToast(data.error || 'Failed to send OTP', 'error');
                    showScreen('email');
                }
            } catch (error) {
                console.error('Continue failed:', error);
                showToast('Connection error. Please try again.', 'error');
            } finally {
                showLoading(document.getElementById('continueBtn'), false);
            }
        });
        
        // Not You Button
        document.getElementById('notYouBtn').addEventListener('click', () => {
            localStorage.removeItem('phishguard_email');
            currentEmail = '';
            showScreen('email');
        });
        
        // Use Different Email
        document.getElementById('useEmailLink').addEventListener('click', (e) => {
            e.preventDefault();
            showScreen('email');
        });
        
        // Email Form Submit
        document.getElementById('emailForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('emailInput').value.trim();
            if (!validateEmail(email)) {
                showInputError(document.getElementById('emailInput'));
                return;
            }
            
            currentEmail = email;
            localStorage.setItem('phishguard_email', email);
            
            try {
                showLoading(document.getElementById('sendOtpBtn'), true);
                
                const response = await fetch('/api/send-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('otpEmail').textContent = email;
                    startOtpTimer();
                    showScreen('otp');
                } else {
                    showToast(data.error || 'Failed to send OTP', 'error');
                }
            } catch (error) {
                console.error('Send OTP failed:', error);
                showToast('Connection error. Please check your network.', 'error');
            } finally {
                showLoading(document.getElementById('sendOtpBtn'), false);
            }
        });
        
        // OTP Input Handling
        setupOtpInputs();
        
        // OTP Form Submit
        document.getElementById('otpForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await verifyOtp();
        });
        
        // Resend OTP
        document.getElementById('resendOtpBtn').addEventListener('click', async () => {
            if (timerSeconds > 0) return;
            
            try {
                const response = await fetch('/api/send-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: currentEmail })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    startOtpTimer();
                    document.getElementById('otpError').classList.remove('show');
                    // Clear OTP inputs
                    document.querySelectorAll('.otp-input').forEach(input => {
                        input.value = '';
                        input.classList.remove('filled', 'error');
                    });
                } else {
                    showToast(data.error || 'Failed to resend OTP', 'error');
                }
            } catch (error) {
                console.error('Resend OTP failed:', error);
                showToast('Connection error. Please try again.', 'error');
            } catch (error) {
                console.error('Resend OTP failed:', error);
                showToast('Connection error. Please try again.', 'error');
            }
        });
        
        // Back Buttons
        document.getElementById('backToEmailBtn').addEventListener('click', () => {
            stopTimer();
            showScreen('email');
        });
        
        document.getElementById('backFromRegisterBtn').addEventListener('click', () => {
            showScreen('email');
        });
        
        // Register Link
        document.getElementById('registerLink').addEventListener('click', (e) => {
            e.preventDefault();
            showScreen('register');
        });
        
        // Login Link
        document.getElementById('loginLink').addEventListener('click', (e) => {
            e.preventDefault();
            showScreen('email');
        });
        
        // Register Form Submit
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const name = document.getElementById('regName').value.trim();
            const email = document.getElementById('regEmail').value.trim();
            const institution = document.getElementById('regInstitution').value.trim();
            const password = document.getElementById('regPassword').value;
            
            if (!validateEmail(email)) {
                showInputError(document.getElementById('regEmail'), 'Please enter a valid email');
                return;
            }
            
            if (password.length < 6) {
                showInputError(document.getElementById('regPassword'), 'Password must be at least 6 characters');
                return;
            }
            
            try {
                showLoading(document.getElementById('registerBtn'), true);
                
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email,
                        password,
                        username: email.split('@')[0],
                        full_name: name,
                        institution
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    currentEmail = email;
                    localStorage.setItem('phishguard_email', email);
                    
                    // Auto-send OTP after registration
                    await sendOtpForLogin(email);
                } else {
                    showToast(data.error || 'Registration failed', 'error');
                }
            } catch (error) {
                console.error('Registration failed:', error);
                showToast('Connection error. Please try again.', 'error');
            } finally {
                showLoading(document.getElementById('registerBtn'), false);
            }
        });
        
        // Forgot Password Link
        document.getElementById('forgotPasswordLink').addEventListener('click', (e) => {
            e.preventDefault();
            showScreen('forgotPassword');
        });
        
        // Back from Forgot Password
        document.getElementById('backFromForgotBtn').addEventListener('click', () => {
            showScreen('email');
        });
        
        // Forgot Password Form Submit
        document.getElementById('forgotPasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('forgotEmailInput').value.trim();
            if (!validateEmail(email)) {
                showInputError(document.getElementById('forgotEmailInput'), 'Please enter a valid email');
                return;
            }
            
            currentEmail = email;
            
            try {
                showLoading(document.getElementById('sendResetOtpBtn'), true);
                
                const response = await fetch('/api/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('resetEmailDisplay').textContent = email;
                    startResetTimer();
                    showScreen('newPassword');
                } else {
                    showToast(data.error || 'Failed to send reset code', 'error');
                }
            } catch (error) {
                console.error('Forgot password failed:', error);
                showToast('Connection error. Please try again.', 'error');
            } finally {
                showLoading(document.getElementById('sendResetOtpBtn'), false);
            }
        });
        
        // Setup Reset OTP Inputs
        setupResetOtpInputs();
        
        // Reset Password Form Submit
        document.getElementById('newPasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await resetPassword();
        });
        
        // Resend Reset OTP
        document.getElementById('resendResetOtpBtn').addEventListener('click', async () => {
            if (resetTimerSeconds > 0) return;
            
            try {
                const response = await fetch('/api/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: currentEmail })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    startResetTimer();
                    document.getElementById('resetPasswordError').classList.remove('show');
                    document.querySelectorAll('#newPasswordScreen .otp-input').forEach(input => {
                        input.value = '';
                        input.classList.remove('filled', 'error');
                    });
                    showToast('Reset code sent!', 'success');
                } else {
                    showToast(data.error || 'Failed to resend code', 'error');
                }
            } catch (error) {
                console.error('Resend reset OTP failed:', error);
                showToast('Connection error. Please try again.', 'error');
            }
        });
        
        // Back from New Password
        document.getElementById('backFromNewPassBtn').addEventListener('click', () => {
            stopResetTimer();
            showScreen('forgotPassword');
        });
    }
    
    // Setup Reset OTP Inputs
    function setupResetOtpInputs() {
        const otpInputs = document.querySelectorAll('#newPasswordScreen .otp-input');
        
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                const value = e.target.value;
                e.target.value = value.replace(/[^0-9]/g, '');
                
                if (e.target.value && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
                
                if (e.target.value) {
                    input.classList.add('filled');
                    input.classList.remove('error');
                } else {
                    input.classList.remove('filled');
                }
            });
            
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !input.value && index > 0) {
                    otpInputs[index - 1].focus();
                }
            });
        });
    }
    
    // Reset Password
    async function resetPassword() {
        const otpInputs = document.querySelectorAll('#newPasswordScreen .otp-input');
        const otp = Array.from(otpInputs).map(input => input.value).join('');
        const newPassword = document.getElementById('newPasswordInput').value;
        const confirmPassword = document.getElementById('confirmPasswordInput').value;
        
        if (otp.length !== 6) {
            showResetError('Please enter all 6 digits');
            otpInputs.forEach(input => input.classList.add('error'));
            return;
        }
        
        if (newPassword.length < 6) {
            showInputError(document.getElementById('newPasswordInput'), 'Password must be at least 6 characters');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            showInputError(document.getElementById('confirmPasswordInput'), 'Passwords do not match');
            return;
        }
        
        try {
            showLoading(document.getElementById('resetPasswordBtn'), true);
            
            const response = await fetch('/api/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    email: currentEmail, 
                    otp, 
                    new_password: newPassword 
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                stopResetTimer();
                showToast('Password reset successful!', 'success');
                
                setTimeout(() => {
                    showScreen('email');
                    document.getElementById('emailInput').value = currentEmail;
                }, 1500);
            } else {
                showResetError(data.error || 'Invalid reset code');
                otpInputs.forEach(input => input.classList.add('error'));
                
                if (data.attempts_left !== undefined) {
                    showResetError(`${data.error}. ${data.attempts_left} attempts remaining.`);
                }
            }
        } catch (error) {
            console.error('Reset password failed:', error);
            showResetError('Connection error. Please try again.');
        } finally {
            showLoading(document.getElementById('resetPasswordBtn'), false);
        }
    }
    
    // Show Reset Error
    function showResetError(message) {
        const errorEl = document.getElementById('resetPasswordError');
        errorEl.textContent = message;
        errorEl.classList.add('show');
    }
    
    // Reset Timer
    function startResetTimer() {
        resetTimerSeconds = 60;
        stopResetTimer();
        
        const timerEl = document.getElementById('resetOtpTimer');
        const timerSecondsEl = document.getElementById('resetTimerSeconds');
        const resendBtn = document.getElementById('resendResetOtpBtn');
        
        timerEl.classList.remove('warning');
        resendBtn.disabled = true;
        
        resetTimerInterval = setInterval(() => {
            resetTimerSeconds--;
            const span = document.getElementById('resetTimerSeconds');
            if (span) span.textContent = resetTimerSeconds;
            
            if (resetTimerSeconds <= 10) {
                timerEl.classList.add('warning');
            }
            
            if (resetTimerSeconds <= 0) {
                stopResetTimer();
                resendBtn.disabled = false;
                timerEl.innerHTML = '<i class="fas fa-check-circle"></i> <span>You can resend now</span>';
            }
        }, 1000);
    }
    
    function stopResetTimer() {
        if (resetTimerInterval) {
            clearInterval(resetTimerInterval);
            resetTimerInterval = null;
        }
    }
    
    // Send OTP for Login
    async function sendOtpForLogin(email) {
        try {
            const response = await fetch('/api/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('otpEmail').textContent = email;
                startOtpTimer();
                showScreen('otp');
            } else {
                showToast(data.error || 'Failed to send OTP', 'error');
            }
        } catch (error) {
            console.error('Send OTP after registration failed:', error);
            showToast('Failed to send OTP. Please try again.', 'error');
        }
    }
    
    // OTP Input Setup
    function setupOtpInputs() {
        const otpInputs = document.querySelectorAll('.otp-input');
        
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                const value = e.target.value;
                
                // Only allow numbers
                e.target.value = value.replace(/[^0-9]/g, '');
                
                if (e.target.value && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
                
                if (e.target.value) {
                    input.classList.add('filled');
                    input.classList.remove('error');
                } else {
                    input.classList.remove('filled');
                }
            });
            
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !input.value && index > 0) {
                    otpInputs[index - 1].focus();
                }
            });
            
            input.addEventListener('paste', (e) => {
                e.preventDefault();
                const pasteData = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
                
                pasteData.split('').forEach((char, i) => {
                    if (otpInputs[i]) {
                        otpInputs[i].value = char;
                        otpInputs[i].classList.add('filled');
                    }
                });
                
                if (pasteData.length > 0) {
                    otpInputs[Math.min(pasteData.length, otpInputs.length - 1)].focus();
                }
            });
        });
    }
    
    // Verify OTP
    async function verifyOtp() {
        const otpInputs = document.querySelectorAll('.otp-input');
        const otp = Array.from(otpInputs).map(input => input.value).join('');
        
        if (otp.length !== 6) {
            showOtpError('Please enter all 6 digits');
            otpInputs.forEach(input => input.classList.add('error'));
            return;
        }
        
        try {
            showLoading(document.getElementById('verifyOtpBtn'), true);
            
            const response = await fetch('/api/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: currentEmail, otp })
            });
            
            const data = await response.json();
            
            if (data.success) {
                stopTimer();
                showScreen('success');
                
                // Store user data
                localStorage.setItem('phishguard_email', currentEmail);
                localStorage.setItem('phishguard_user', JSON.stringify(data.user));
                
                // Redirect after animation
                setTimeout(() => {
                    window.location.href = '/';
                }, 2500);
            } else {
                showOtpError(data.error || 'Invalid OTP');
                otpInputs.forEach(input => input.classList.add('error'));
                
                if (data.attempts_left !== undefined) {
                    showOtpError(`${data.error}. ${data.attempts_left} attempts remaining.`);
                }
            }
        } catch (error) {
            console.error('Verify OTP failed:', error);
            showOtpError('Connection error. Please try again.');
        } finally {
            showLoading(document.getElementById('verifyOtpBtn'), false);
        }
    }
    
    // OTP Timer
    function startOtpTimer() {
        timerSeconds = 60;
        stopTimer();
        
        const timerEl = document.getElementById('otpTimer');
        const timerSecondsEl = document.getElementById('timerSeconds');
        const resendBtn = document.getElementById('resendOtpBtn');
        
        timerEl.classList.remove('warning');
        resendBtn.disabled = true;
        timerEl.innerHTML = '<i class="fas fa-clock"></i> <span>Resend available in <strong id="timerSeconds">60</strong>s</strong></span>';
        
        timerInterval = setInterval(() => {
            timerSeconds--;
            const span = document.getElementById('timerSeconds');
            if (span) span.textContent = timerSeconds;
            
            if (timerSeconds <= 10) {
                timerEl.classList.add('warning');
            }
            
            if (timerSeconds <= 0) {
                stopTimer();
                resendBtn.disabled = false;
                timerEl.innerHTML = '<i class="fas fa-check-circle"></i> <span>You can resend now</span>';
            }
        }, 1000);
    }
    
    function stopTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }
    
    // Show OTP Error
    function showOtpError(message) {
        const errorEl = document.getElementById('otpError');
        errorEl.textContent = message;
        errorEl.classList.add('show');
    }
    
    // Show Loading State
    function showLoading(btn, loading) {
        if (loading) {
            btn.classList.add('loading');
            btn.disabled = true;
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }
    
    // Validate Email
    function validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
    
    // Show Input Error
    function showInputError(input, message) {
        input.style.borderColor = '#ff4757';
        input.style.animation = 'shake 0.5s ease';
        input.focus();
        
        if (message) {
            showToast(message, 'error');
        }
        
        setTimeout(() => {
            input.style.borderColor = '';
            input.style.animation = '';
        }, 2000);
    }
    
    // Toast notification function
    function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
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
}
