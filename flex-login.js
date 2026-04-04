// =============================================
// PHISHGUARD AI - FLEXIBLE LOGIN SYSTEM
// Password OR OTP Login
// =============================================

document.addEventListener('DOMContentLoaded', () => {
    initLoginSystem();
});

function initLoginSystem() {
    // State
    let currentMethod = 'password';
    let currentEmail = '';
    let timerInterval = null;
    let timerSeconds = 60;
    let loginAttempts = 0;
    
    // Check for saved email
    checkSavedEmail();
    
    // Initialize event listeners
    initEventListeners();
    
    // Check saved email
    function checkSavedEmail() {
        const savedEmail = localStorage.getItem('phishguard_email');
        const banner = document.getElementById('autoLoginBanner');
        
        if (savedEmail) {
            document.getElementById('savedEmailText').textContent = savedEmail;
            document.getElementById('pwdEmail').value = savedEmail;
            document.getElementById('otpEmail').value = savedEmail;
            banner.style.display = 'flex';
        } else {
            banner.style.display = 'none';
        }
    }
    
    // Event Listeners
    function initEventListeners() {
        // Method selector
        document.querySelectorAll('.method-btn').forEach(btn => {
            btn.addEventListener('click', () => switchMethod(btn.dataset.method));
        });
        
        // Auto login buttons
        document.getElementById('useSavedAccount').addEventListener('click', useSavedAccount);
        document.getElementById('differentAccount').addEventListener('click', differentAccount);
        
        // Password login
        document.getElementById('loginPasswordForm').addEventListener('submit', loginWithPassword);
        document.getElementById('togglePwd').addEventListener('click', togglePasswordVisibility);
        
        // OTP login
        document.getElementById('sendOtpForm').addEventListener('submit', sendOtp);
        document.getElementById('verifyOtpForm').addEventListener('submit', verifyOtp);
        document.getElementById('resendOtpBtn').addEventListener('click', resendOtp);
        setupOtpInputs();
        
        // Forgot password
        document.getElementById('forgotLink').addEventListener('click', showForgotForm);
        document.getElementById('resetForm').addEventListener('submit', resetPassword);
        document.getElementById('backFromReset').addEventListener('click', () => showForm('password'));
        
        // Registration
        document.getElementById('createAccountLink').addEventListener('click', showRegisterForm);
        document.getElementById('signupForm').addEventListener('submit', registerUser);
        document.getElementById('backToLogin').addEventListener('click', () => showForm('password'));
        
        // Password strength
        document.getElementById('regPassword')?.addEventListener('input', checkPasswordStrength);
        
        // Toggle password visibility for register
        document.querySelectorAll('.toggle-pwd[data-target]').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = document.getElementById(btn.dataset.target);
                togglePassword(target, btn);
            });
        });
    }
    
    // Switch between login methods
    function switchMethod(method) {
        currentMethod = method;
        
        document.querySelectorAll('.method-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.method === method);
        });
        
        document.getElementById('passwordForm').classList.toggle('active', method === 'password');
        document.getElementById('otpForm').classList.toggle('active', method === 'otp');
        
        // Clear errors
        hideErrors();
    }
    
    // Use saved account
    function useSavedAccount() {
        const email = localStorage.getItem('phishguard_email');
        if (email) {
            currentEmail = email;
            document.getElementById('pwdEmail').value = email;
            document.getElementById('otpEmail').value = email;
            document.getElementById('otpSentTo').textContent = email;
        }
    }
    
    // Use different account
    function differentAccount() {
        localStorage.removeItem('phishguard_email');
        document.getElementById('autoLoginBanner').style.display = 'none';
        document.getElementById('pwdEmail').value = '';
        document.getElementById('otpEmail').value = '';
        currentEmail = '';
    }
    
    // Login with Password
    async function loginWithPassword(e) {
        e.preventDefault();
        
        const email = document.getElementById('pwdEmail').value.trim();
        const password = document.getElementById('pwdPassword').value;
        const remember = document.getElementById('rememberPwd').checked;
        
        if (!validateEmail(email)) {
            showError('pwdError', 'Please enter a valid email address');
            return;
        }
        
        if (!password) {
            showError('pwdError', 'Please enter your password');
            return;
        }
        
        const btn = document.getElementById('loginPwdBtn');
        setButtonLoading(btn, true);
        
        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: email, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                if (remember) {
                    localStorage.setItem('phishguard_email', email);
                }
                
                loginAttempts = 0;
                showSuccess();
            } else {
                loginAttempts++;
                showError('pwdError', data.error || 'Invalid credentials');
                
                if (loginAttempts >= 3) {
                    showError('pwdError', 'Too many attempts. Please try OTP login or wait.');
                }
            }
        } catch (error) {
            showError('pwdError', 'Connection error. Please try again.');
        } finally {
            setButtonLoading(btn, false);
        }
    }
    
    // Send OTP
    async function sendOtp(e) {
        e.preventDefault();
        
        const email = document.getElementById('otpEmail').value.trim();
        
        if (!validateEmail(email)) {
            showError('otpError', 'Please enter a valid email address');
            return;
        }
        
        const btn = document.getElementById('sendOtpBtn');
        setButtonLoading(btn, true);
        
        try {
            const response = await fetch('/api/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            
            const data = await response.json();
            
            if (data.success) {
                currentEmail = email;
                document.getElementById('otpSentTo').textContent = email;
                document.getElementById('otpInputSection').style.display = 'block';
                document.getElementById('sendOtpBtn').style.display = 'none';
                startTimer();
                
                // Focus first OTP input
                setTimeout(() => {
                    document.querySelector('.otp-digit').focus();
                }, 100);
            } else {
                showError('otpError', data.error || 'Failed to send OTP');
            }
        } catch (error) {
            showError('otpError', 'Connection error. Please try again.');
        } finally {
            setButtonLoading(btn, false);
        }
    }
    
    // Verify OTP
    async function verifyOtp(e) {
        e.preventDefault();
        
        const otpInputs = document.querySelectorAll('.otp-digit');
        const otp = Array.from(otpInputs).map(input => input.value).join('');
        
        if (otp.length !== 6) {
            showError('otpError', 'Please enter all 6 digits');
            otpInputs.forEach(input => input.classList.add('error'));
            return;
        }
        
        const btn = document.getElementById('verifyOtpBtn');
        setButtonLoading(btn, true);
        
        try {
            const response = await fetch('/api/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: currentEmail, otp })
            });
            
            const data = await response.json();
            
            if (data.success) {
                localStorage.setItem('phishguard_email', currentEmail);
                stopTimer();
                showSuccess();
            } else {
                showError('otpError', data.error || 'Invalid OTP');
                otpInputs.forEach(input => input.classList.add('error'));
                setTimeout(() => {
                    otpInputs.forEach(input => input.classList.remove('error'));
                }, 500);
            }
        } catch (error) {
            showError('otpError', 'Connection error. Please try again.');
        } finally {
            setButtonLoading(btn, false);
        }
    }
    
    // Resend OTP
    async function resendOtp() {
        await sendOtp({ preventDefault: () => {} });
    }
    
    // Setup OTP inputs
    function setupOtpInputs() {
        const otpInputs = document.querySelectorAll('.otp-digit');
        
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                const value = e.target.value.replace(/[^0-9]/g, '');
                e.target.value = value;
                
                if (value && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
                
                input.classList.toggle('filled', !!value);
            });
            
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !input.value && index > 0) {
                    otpInputs[index - 1].focus();
                }
            });
            
            input.addEventListener('paste', (e) => {
                e.preventDefault();
                const paste = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
                
                paste.split('').forEach((char, i) => {
                    if (otpInputs[i]) {
                        otpInputs[i].value = char;
                        otpInputs[i].classList.add('filled');
                    }
                });
                
                if (paste.length > 0) {
                    otpInputs[Math.min(paste.length, 5)].focus();
                }
            });
        });
    }
    
    // Timer
    function startTimer() {
        timerSeconds = 60;
        stopTimer();
        
        const fill = document.getElementById('timerFill');
        const value = document.getElementById('timerValue');
        const resendBtn = document.getElementById('resendOtpBtn');
        const timerBar = document.querySelector('.otp-timer-bar');
        
        timerBar.style.display = 'flex';
        resendBtn.disabled = true;
        fill.style.width = '100%';
        
        timerInterval = setInterval(() => {
            timerSeconds--;
            value.textContent = timerSeconds;
            fill.style.width = `${(timerSeconds / 60) * 100}%`;
            
            if (timerSeconds <= 0) {
                stopTimer();
                resendBtn.disabled = false;
                fill.style.width = '0%';
            }
        }, 1000);
    }
    
    function stopTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }
    
    // Register
    async function registerUser(e) {
        e.preventDefault();
        
        const email = document.getElementById('regEmail').value.trim();
        const password = document.getElementById('regPassword').value;
        
        if (!validateEmail(email)) {
            showError('regError', 'Please enter a valid email address');
            return;
        }
        
        if (!validatePassword(password)) {
            showError('regError', 'Password does not meet requirements');
            return;
        }
        
        const btn = document.getElementById('registerBtn');
        setButtonLoading(btn, true);
        
        try {
            const response = await fetch('/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    password,
                    username: email.split('@')[0]
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                localStorage.setItem('phishguard_email', email);
                showSuccess();
            } else {
                showError('regError', data.error || 'Registration failed');
            }
        } catch (error) {
            showError('regError', 'Connection error. Please try again.');
        } finally {
            setButtonLoading(btn, false);
        }
    }
    
    // Reset Password
    async function resetPassword(e) {
        e.preventDefault();
        
        const email = document.getElementById('resetEmail').value.trim();
        
        if (!validateEmail(email)) {
            showError('resetError', 'Please enter a valid email address');
            return;
        }
        
        const btn = document.getElementById('resetBtn');
        setButtonLoading(btn, true);
        
        try {
            // Simulated - in real app, this would send reset email
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            document.getElementById('resetSuccess').textContent = 'Password reset link sent to your email!';
            document.getElementById('resetSuccess').classList.add('show');
            document.getElementById('resetError').classList.remove('show');
            
            setTimeout(() => {
                showForm('password');
            }, 3000);
        } catch (error) {
            showError('resetError', 'Connection error. Please try again.');
        } finally {
            setButtonLoading(btn, false);
        }
    }
    
    // Password Strength
    function checkPasswordStrength() {
        const password = document.getElementById('regPassword').value;
        const fill = document.getElementById('strengthFill');
        const label = document.getElementById('strengthLabel');
        const rules = document.querySelectorAll('.password-rules li');
        
        const checks = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };
        
        let strength = 0;
        Object.values(checks).forEach(valid => { if (valid) strength++; });
        
        const levels = ['weak', 'fair', 'good', 'strong'];
        const labels = ['Weak', 'Fair', 'Good', 'Strong'];
        
        fill.className = 'strength-fill ' + (strength > 0 ? levels[strength - 1] : '');
        label.textContent = strength > 0 ? labels[strength - 1] : 'Password strength';
        
        rules.forEach(rule => {
            const req = rule.dataset.rule;
            const isValid = checks[req];
            rule.classList.toggle('valid', isValid);
            rule.querySelector('i').className = isValid ? 'fas fa-check-circle' : 'fas fa-circle';
        });
    }
    
    function validatePassword(password) {
        return password.length >= 8 &&
               /[A-Z]/.test(password) &&
               /[0-9]/.test(password) &&
               /[!@#$%^&*(),.?":{}|<>]/.test(password);
    }
    
    // Show/Hide forms
    function showForm(form) {
        const forms = ['password', 'otp', 'forgot', 'register'];
        forms.forEach(f => {
            const el = document.getElementById(f + 'Form');
            if (el) el.classList.remove('active');
        });
        
        if (form !== 'success') {
            document.getElementById(form + 'Form')?.classList.add('active');
        }
        
        document.getElementById('methodSelector').style.display = form === 'password' ? 'block' : 'none';
        document.getElementById('formFooter').style.display = form === 'password' ? 'flex' : 'none';
        
        hideErrors();
    }
    
    function showForgotForm(e) {
        e.preventDefault();
        showForm('forgot');
    }
    
    function showRegisterForm(e) {
        e.preventDefault();
        showForm('register');
    }
    
    // Success
    function showSuccess() {
        document.getElementById('passwordForm').classList.remove('active');
        document.getElementById('otpForm').classList.remove('active');
        document.getElementById('successScreen').classList.add('active');
        document.getElementById('methodSelector').style.display = 'none';
        document.getElementById('formFooter').style.display = 'none';
        document.getElementById('autoLoginBanner').style.display = 'none';
        
        setTimeout(() => {
            window.location.href = '/';
        }, 2500);
    }
    
    // Helpers
    function showError(elementId, message) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = message;
            el.classList.add('show');
        }
    }
    
    function hideErrors() {
        document.querySelectorAll('.error-alert, .success-alert').forEach(el => {
            el.classList.remove('show');
        });
    }
    
    function setButtonLoading(btn, loading) {
        btn.classList.toggle('loading', loading);
        btn.disabled = loading;
    }
    
    function togglePasswordVisibility() {
        const input = document.getElementById('pwdPassword');
        const icon = document.getElementById('togglePwd').querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }
    
    function togglePassword(input, btn) {
        if (input.type === 'password') {
            input.type = 'text';
            btn.querySelector('i').className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            btn.querySelector('i').className = 'fas fa-eye';
        }
    }
    
    function validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
}
