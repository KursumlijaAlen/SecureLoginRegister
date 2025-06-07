<?php require '../config_default.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - SSSD Project</title>
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
            line-height: 1.5;
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
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .message {
            margin-top: 15px;
            padding: 12px;
            border-radius: 10px;
            text-align: center;
            font-weight: 500;
        }
        
        .error {
            background: linear-gradient(45deg, #ffebee, #fce4ec);
            color: #c62828;
            border: 1px solid #ef9a9a;
        }
        
        .success {
            background: linear-gradient(45deg, #e8f5e8, #f1f8e9);
            color: #2e7d32;
            border: 1px solid #81c784;
        }
        
        .warning {
            background: linear-gradient(45deg, #fff3e0, #fff8e1);
            color: #ef6c00;
            border: 1px solid #ffb74d;
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
        
        .info-box {
            background: linear-gradient(45deg, #e3f2fd, #f3e5f5);
            border: 2px solid #bbdefb;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            color: #1565c0;
        }
        
        .info-box h3 {
            margin-bottom: 10px;
            color: #1565c0;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .info-box ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .info-box li {
            margin-bottom: 5px;
        }
        
        .password-strength {
            margin-top: 8px;
            font-size: 14px;
        }
        
        .strength-bar {
            height: 4px;
            border-radius: 2px;
            margin-top: 5px;
            transition: all 0.3s ease;
        }
        
        .strength-weak { background: #f44336; width: 25%; }
        .strength-fair { background: #ff9800; width: 50%; }
        .strength-good { background: #2196f3; width: 75%; }
        .strength-strong { background: #4caf50; width: 100%; }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .countdown {
            text-align: center;
            font-size: 18px;
            color: #28a745;
            margin-top: 15px;
            font-weight: 600;
        }
        
        .icon {
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Reset Password</h1>
            <p>Create a new secure password for your account</p>
        </div>
        
        <div class="info-box">
            <h3><span class="icon">🛡️</span> Security Requirements</h3>
            <ul>
                <li>Minimum 8 characters long</li>
                <li>Cannot be a previously compromised password</li>
                <li>Must be different from your current password</li>
                <li>Consider using a mix of letters, numbers, and symbols</li>
            </ul>
        </div>
        
        <div id="invalidTokenMessage" class="message error" style="display: none;">
            <strong>Invalid Reset Link</strong><br>
            This password reset link is invalid or has expired. Please request a new one.
        </div>
        
        <form id="resetPasswordForm">
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="password" required minlength="8" 
                       placeholder="Enter your new password">
                <div id="passwordStrength" class="password-strength"></div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required 
                       placeholder="Confirm your new password">
            </div>
            
            <button type="submit" class="btn" id="submitBtn">
                Reset Password
            </button>
            
            <div id="message"></div>
            
            <div id="successCountdown" class="countdown" style="display: none;">
                Redirecting to login in <span id="countdownNumber">3</span> seconds...
            </div>
        </form>
        
        <div class="auth-links">
            <p>
                <a href="login.php">← Back to Login</a> |
                <a href="register.php">Create New Account</a>
            </p>
        </div>
    </div>

    <script>
        const API_BASE = '../api';
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');

        // Check if token exists
        if (!token) {
            document.getElementById('invalidTokenMessage').style.display = 'block';
            document.getElementById('resetPasswordForm').style.display = 'none';
        }

        // Password strength checker
        function checkPasswordStrength(password) {
            const strengthEl = document.getElementById('passwordStrength');
            let strength = 0;
            let feedback = [];

            if (password.length >= 8) strength++;
            if (password.match(/[a-z]/)) strength++;
            if (password.match(/[A-Z]/)) strength++;
            if (password.match(/[0-9]/)) strength++;
            if (password.match(/[^a-zA-Z0-9]/)) strength++;

            const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
            const colors = ['strength-weak', 'strength-weak', 'strength-fair', 'strength-good', 'strength-strong'];
            
            strengthEl.innerHTML = `
                <div>Password Strength: <strong>${levels[strength] || 'Very Weak'}</strong></div>
                <div class="strength-bar ${colors[strength] || 'strength-weak'}"></div>
            `;
        }

        // Real-time password strength checking
        document.getElementById('new_password').addEventListener('input', (e) => {
            checkPasswordStrength(e.target.value);
        });

        // Form submission
        document.getElementById('resetPasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const password = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const messageEl = document.getElementById('message');
            const submitBtn = document.getElementById('submitBtn');

            // Validation
            if (password !== confirmPassword) {
                messageEl.innerHTML = '<div class="message error">❌ Passwords do not match</div>';
                return;
            }

            if (password.length < 8) {
                messageEl.innerHTML = '<div class="message error">❌ Password must be at least 8 characters long</div>';
                return;
            }

            // Show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="loading"></span> Resetting Password...';

            try {
                const response = await fetch(`${API_BASE}/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, password })
                });

                const result = await response.json();

                if (response.ok) {
                    messageEl.innerHTML = `
                        <div class="message success">
                            <strong>✅ Password Reset Successful!</strong><br>
                            Your password has been updated successfully.
                        </div>
                    `;
                    
                    // Hide form and show countdown
                    document.getElementById('resetPasswordForm').style.display = 'none';
                    document.getElementById('successCountdown').style.display = 'block';
                    
                    // Countdown and redirect
                    let countdown = 3;
                    const countdownEl = document.getElementById('countdownNumber');
                    const countdownInterval = setInterval(() => {
                        countdown--;
                        countdownEl.textContent = countdown;
                        
                        if (countdown <= 0) {
                            clearInterval(countdownInterval);
                            window.location.href = 'login.php';
                        }
                    }, 1000);
                    
                } else {
                    let errorMessage = result.error;
                    
                    // Customize error messages
                    if (errorMessage.includes('expired')) {
                        errorMessage = '⏰ This reset link has expired. Please request a new password reset.';
                    } else if (errorMessage.includes('compromised')) {
                        errorMessage = '🚫 This password has been found in data breaches. Please choose a different password.';
                    } else if (errorMessage.includes('Invalid')) {
                        errorMessage = '❌ Invalid or expired reset token. Please request a new password reset.';
                    }
                    
                    messageEl.innerHTML = `<div class="message error">${errorMessage}</div>`;
                }
            } catch (error) {
                messageEl.innerHTML = `
                    <div class="message error">
                        <strong>❌ Network Error</strong><br>
                        Unable to connect to the server. Please check your connection and try again.
                    </div>
                `;
            } finally {
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Reset Password';
            }
        });

        // Real-time password matching feedback
        document.getElementById('confirm_password').addEventListener('input', (e) => {
            const password = document.getElementById('new_password').value;
            const confirmPassword = e.target.value;
            
            if (confirmPassword && password !== confirmPassword) {
                e.target.style.borderColor = '#f44336';
            } else {
                e.target.style.borderColor = '#e1e5e9';
            }
        });

        // Focus on first input
        if (token) {
            document.getElementById('new_password').focus();
        }
    </script>
</body>
</html>