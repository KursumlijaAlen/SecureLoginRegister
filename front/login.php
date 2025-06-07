<?php require '../config_default.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SSSD Project</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 450px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 1rem;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 8px;
            text-align: center;
        }
        
        .error {
            background-color: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }
        
        .success {
            background-color: #efe;
            color: #363;
            border: 1px solid #cfc;
        }
        
        .auth-links {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .auth-links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
            margin: 0 10px;
        }
        
        .auth-links a:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        .hidden {
            display: none;
        }
        
        .captcha-container {
            margin: 20px 0;
            text-align: center;
        }
        
        .otp-container {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 30px;
            margin-top: 20px;
            text-align: center;
        }
        
        .qr-code {
            margin: 20px 0;
        }
        
        .qr-code img {
            max-width: 200px;
            border-radius: 10px;
        }

        .method-selection {
            margin: 20px 0;
        }

        .method-option {
            background: white;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .method-option:hover {
            border-color: #667eea;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
            transform: translateY(-2px);
        }

        .method-option.selected {
            border-color: #667eea;
            background: linear-gradient(45deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
        }

        .method-icon {
            font-size: 2rem;
            min-width: 60px;
            text-align: center;
        }

        .method-info h4 {
            margin: 0 0 5px 0;
            color: #333;
            font-size: 1.1rem;
        }

        .method-info p {
            margin: 0;
            color: #666;
            font-size: 0.9rem;
        }

        .code-input {
            margin-top: 20px;
        }

        .sending-code {
            opacity: 0.6;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login Form -->
        <div id="loginSection">
            <div class="header">
                <h1>Welcome Back</h1>
                <p>Sign in to your account</p>
            </div>
            
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username or Email</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div id="captchaContainer" class="captcha-container hidden">
                    <div class="h-captcha" data-sitekey="<?php echo HCAPTCHA_SITE_KEY; ?>"></div>
                </div>
                
                <button type="submit" class="btn">Sign In</button>

                <button type="button" id="googleLoginBtn" class="btn" style="margin-top:1rem; background:#4285F4;">Sign in with Google</button>
                
                <div id="loginMessage"></div>
            </form>
            
            <div class="auth-links">
                <p>
                    <a href="forgot-password.php">Forgot Password?</a> |
                    <a href="register.php">Create Account</a>
                </p>
            </div>
        </div>

        <!-- 2FA Section -->
        <div id="otpSection" class="otp-container hidden">
        <h2>🔐 Choose Your 2FA Method</h2>
        <p>Select how you'd like to receive your verification code</p>
        
        <!-- Method Selection -->
        <div id="methodSelection" class="method-selection">
            <div id="methodsList"></div>
            <div id="methodMessage"></div>
        </div>
        
        <!-- Code Input (initially hidden) -->
        <div id="codeInput" class="code-input hidden">
            <h3 id="codeInputTitle">Enter Verification Code</h3>
            <p id="codeInputDescription"></p>
            
            <form id="otpForm">
                <div class="form-group">
                    <label for="otp_code">Verification Code</label>
                    <input type="text" id="otp_code" name="otp" maxlength="8" placeholder="000000" required>
                </div>
                
                <input type="hidden" id="selected_method" name="method" value="">
                
                <button type="submit" class="btn">Verify Code</button>
                
                <div id="otpMessage"></div>
            </form>
            
            <div class="auth-links">
                <p>
                    <a href="#" onclick="goBackToMethods()">← Choose Different Method</a> |
                    <a href="#" onclick="goBackToLogin()">← Back to Login</a>
                </p>
            </div>
        </div>
        
        <!-- QR Code for TOTP Setup -->
        <div id="qrCodeContainer" class="qr-code hidden">
            <h3>📱 Set Up Authenticator App</h3>
            <p>Scan this QR code with your authenticator app:</p>
            <img id="qrCodeImage" src="" alt="QR Code">
            <div class="auth-links">
                <p><a href="#" onclick="skipQRSetup()">Continue when you scan or if you have already scanned the qr code</a></p>
            </div>
        </div>
    </div>

    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <script>
        const API_BASE = '../api';

       // Updated JavaScript for login.php to handle Google SSO + 2FA

        // 1) Google Login Button Handler
        document.getElementById('googleLoginBtn')?.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_BASE}/google-login`);
                const { authUrl, error } = await res.json();
                if (authUrl) {
                    window.location.href = authUrl;
                } else {
                    alert(error || 'Could not get Google login URL');
                }
            } catch (e) {
                console.error(e);
                alert('Network error while starting Google login');
            }
        });

        // 2) On page load, handle Google callback
        window.addEventListener('DOMContentLoaded', async () => {
            const params = new URLSearchParams(window.location.search);
            if (!params.has('code')) return;
            
            const code = params.get('code');
            const msg = document.getElementById('loginMessage');
            msg.innerHTML = '<div class="message">Finishing Google sign-in…</div>';
            
            try {
                const res = await fetch(`${API_BASE}/google-callback?code=${encodeURIComponent(code)}`);
                const result = await res.json();
                
                console.log('Google callback result:', result); // Debug log
                
                if (res.ok) {
                    if (result.requires_2fa) {
                        // Show 2FA section for Google SSO users
                        document.getElementById('loginSection').classList.add('hidden');
                        document.getElementById('otpSection').classList.remove('hidden');
                        
                        // Check if this response includes a QR code (new user setup)
                        if (result.qr_code_url) {
                            // New user - show QR code for setup
                            console.log('Showing QR code for new user setup');
                            document.getElementById('qrCodeImage').src = result.qr_code_url;
                            document.getElementById('qrCodeContainer').classList.remove('hidden');
                            document.getElementById('methodSelection').classList.add('hidden');
                            
                            // Update the message in the QR code section
                            const otpMessage = document.getElementById('methodMessage');
                            if (otpMessage) {
                                otpMessage.innerHTML = `<div class="message success">${result.message}</div>`;
                            }
                        } else {
                            // Existing user - load available 2FA methods
                            console.log('Loading 2FA methods for existing user');
                            load2FAMethods();
                            
                            // Update message
                            const methodMessage = document.getElementById('methodMessage');
                            if (methodMessage) {
                                methodMessage.innerHTML = `<div class="message success">${result.message}</div>`;
                            }
                        }
                    } else {
                        // Something unexpected happened
                        console.error('Unexpected response:', result);
                        msg.innerHTML = `<div class="message error">Unexpected response from server</div>`;
                    }
                } else {
                    console.error('Error response:', result);
                    msg.innerHTML = `<div class="message error">${result.error || 'Google sign-in failed.'}</div>`;
                }
            } catch (e) {
                console.error('Network error:', e);
                msg.innerHTML = `<div class="message error">Network error completing Google login.</div>`;
            }
            
            // Clean up URL after processing
            window.history.replaceState({}, document.title, window.location.pathname);
        });
        
        // Enhanced 2FA variables
        let available2FAMethods = [];
        let selectedMethod = null;

        // Login Form Handler (Enhanced)
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData       = new FormData(e.target);
        const data           = Object.fromEntries(formData);
        const messageEl      = document.getElementById('loginMessage');
        const captchaContainer = document.getElementById('captchaContainer');

        // If captcha is showing, require it before even calling /login
        if (!captchaContainer.classList.contains('hidden')) {
            const captchaResp = hcaptcha.getResponse();
            if (!captchaResp) {
            messageEl.innerHTML =
                '<div class="message error">Please complete the captcha before logging in.</div>';
            return;
            }
            data['h-captcha-response'] = captchaResp;
        }

        try {
            const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
            });
            const result = await response.json();

            if (response.ok) {
            if (result.requires_2fa) {
                // Show 2FA section
                document.getElementById('loginSection').classList.add('hidden');
                document.getElementById('otpSection').classList.remove('hidden');
                load2FAMethods();
                if (result.qr_code_url) {
                document.getElementById('qrCodeImage').src = result.qr_code_url;
                document.getElementById('qrCodeContainer').classList.remove('hidden');
                }
                messageEl.innerHTML = `<div class="message success">${result.message}</div>`;
            } else {
                window.location.href = 'dashboard.php';
            }
            } else {
            // Display the error
            messageEl.innerHTML = `<div class="message error">${result.error}</div>`;
            // If server says we now need captcha, keep it visible
            if (result.requires_captcha || /captcha/i.test(result.error)) {
                captchaContainer.classList.remove('hidden');
                // re-render widget if needed
                setTimeout(() => {
                if (window.hcaptcha) {
                    const captchaEl = captchaContainer.querySelector('.h-captcha');
                    if (captchaEl && !captchaEl.querySelector('iframe')) {
                    hcaptcha.render(captchaEl);
                    }
                }
                }, 100);
            }
            }
        } catch (error) {
            messageEl.innerHTML =
            `<div class="message error">Network error occurred. Please try again.</div>`;
        } finally {
            // 🔄 Force a new captcha challenge on every attempt
            if (!captchaContainer.classList.contains('hidden') && window.hcaptcha) {
            hcaptcha.reset();
            }
        }
        });



        // ✅ NEW: Load available 2FA methods
        async function load2FAMethods() {
            try {
                const response = await fetch(`${API_BASE}/user/2fa-methods`);
                const result = await response.json();
                
                if (response.ok) {
                    available2FAMethods = result.methods;
                    displayMethodOptions();
                } else {
                    document.getElementById('methodMessage').innerHTML = 
                        `<div class="message error">${result.error}</div>`;
                }
            } catch (error) {
                document.getElementById('methodMessage').innerHTML = 
                    `<div class="message error">Error loading 2FA methods</div>`;
            }
        }

        // ✅ NEW: Display method selection options
        function displayMethodOptions() {
            const methodsList = document.getElementById('methodsList');
            
            if (available2FAMethods.length === 0) {
                methodsList.innerHTML = '<p>No 2FA methods available. Please contact support.</p>';
                return;
            }
            
            const methodsHTML = available2FAMethods.map(method => `
                <div class="method-option" onclick="selectMethod('${method.type}')">
                    <div class="method-icon">${method.icon}</div>
                    <div class="method-info">
                        <h4>${method.name}</h4>
                        <p>${method.description}</p>
                    </div>
                </div>
            `).join('');
            
            methodsList.innerHTML = methodsHTML;
        }

        // ✅ NEW: Select 2FA method
        async function selectMethod(methodType) {
            selectedMethod = methodType;
            
            // Highlight selected method
            document.querySelectorAll('.method-option').forEach(option => {
                option.classList.remove('selected');
            });
            event.currentTarget.classList.add('selected');
            
            if (methodType === 'totp') {
                // Show code input directly for TOTP
                showCodeInput(methodType, 'Enter the 6-digit code from your authenticator app');
            } else if (methodType === 'backup') {
                // Show code input for backup codes
                showCodeInput(methodType, 'Enter one of your backup recovery codes');
            } else {
                // Send code for SMS/Email
                await sendVerificationCode(methodType);
            }
        }

        // ✅ NEW: Send verification code
        async function sendVerificationCode(method) {
            const messageEl = document.getElementById('methodMessage');
            
            try {
                messageEl.innerHTML = '<div class="message">Sending verification code...</div>';
                
                const response = await fetch(`${API_BASE}/user/send-2fa-code`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ method: method })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showCodeInput(method, `Code sent to ${result.destination}`);
                    messageEl.innerHTML = `<div class="message success">${result.message}</div>`;
                } else {
                    messageEl.innerHTML = `<div class="message error">${result.error}</div>`;
                }
            } catch (error) {
                messageEl.innerHTML = '<div class="message error">Failed to send verification code</div>';
            }
        }

        // ✅ NEW: Show code input form
        function showCodeInput(method, description) {
            document.getElementById('methodSelection').classList.add('hidden');
            document.getElementById('codeInput').classList.remove('hidden');
            
            document.getElementById('codeInputTitle').textContent = 
                method === 'backup' ? 'Enter Backup Code' : 'Enter Verification Code';
            document.getElementById('codeInputDescription').textContent = description;
            document.getElementById('selected_method').value = method;
            
            // Focus on input
            document.getElementById('otp_code').focus();
        }

        // ✅ NEW: Go back to method selection
        function goBackToMethods() {
            document.getElementById('codeInput').classList.add('hidden');
            document.getElementById('methodSelection').classList.remove('hidden');
            document.getElementById('otpForm').reset();
            document.getElementById('otpMessage').innerHTML = '';
        }

        // Enhanced OTP Form Handler
        document.getElementById('otpForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            const messageEl = document.getElementById('otpMessage');

            try {
                const response = await fetch(`${API_BASE}/verify-otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (response.ok) {
                    messageEl.innerHTML = `<div class="message success">${result.message}</div>`;
                    
                    // Store token and redirect
                    if (result.token) {
                        localStorage.setItem('auth_token', result.token);
                    }
                    
                    setTimeout(() => {
                        window.location.href = 'dashboard.php';
                    }, 1500);
                } else {
                    messageEl.innerHTML = `<div class="message error">${result.error}</div>`;
                }
            } catch (error) {
                messageEl.innerHTML = `<div class="message error">Network error occurred. Please try again.</div>`;
            }
        });

        // Existing function (keep this)
        function goBackToLogin() {
            document.getElementById('otpSection').classList.add('hidden');
            document.getElementById('loginSection').classList.remove('hidden');
            document.getElementById('loginForm').reset();
            document.getElementById('loginMessage').innerHTML = '';
        }

        function skipQRSetup() {
            // Hide QR code container
            document.getElementById('qrCodeContainer').classList.add('hidden');
            
            // Show the TOTP code input directly
            showCodeInput('totp', 'Enter the 6-digit code from your authenticator app');
        }
    </script>
</body>
</html>