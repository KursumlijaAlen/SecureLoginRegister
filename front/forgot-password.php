<?php require '../config_default.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - SSSD Project</title>
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
        
        .info-box {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #1565c0;
        }
        
        .info-box strong {
            display: block;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reset Password</h1>
            <p>Enter your email address and we'll send you a link to reset your password</p>
        </div>
        
        <div class="info-box">
            <strong>Security Notice:</strong>
            Reset links expire in 5 minutes and can only be used once. After 2 attempts, you'll need to complete a captcha.
        </div>
        
        <form id="forgotPasswordForm">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div id="captchaContainer" class="captcha-container hidden">
                <div class="h-captcha" data-sitekey="<?php echo HCAPTCHA_SITE_KEY; ?>"></div>
            </div>
            
            <button type="submit" class="btn">Send Reset Link</button>
            
            <div id="message"></div>
        </form>
        
        <div class="auth-links">
            <p>
                <a href="login.php">← Back to Login</a> |
                <a href="register.php">Create Account</a>
            </p>
        </div>
    </div>

    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <script>
        const API_BASE = '../api';
        let attemptCount = 0;

        const form = document.getElementById('forgotPasswordForm');
        const captchaContainer = document.getElementById('captchaContainer');
        const messageEl = document.getElementById('message');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            messageEl.innerHTML = '';
            attemptCount++;

            // After 2 attempts, require and show captcha
            if (attemptCount >= 2) {
                captchaContainer.classList.remove('hidden');
                // Ensure captcha widget is rendered
                setTimeout(() => {
                    if (typeof hcaptcha !== 'undefined') {
                        const widget = captchaContainer.querySelector('.h-captcha');
                        if (widget && !widget.querySelector('iframe')) {
                            hcaptcha.render(widget);
                        }
                    }
                }, 100);

                // Must solve captcha before proceeding
                const captchaResp = hcaptcha.getResponse();
                if (!captchaResp) {
                    return messageEl.innerHTML =
                        '<div class="message error">Please complete the captcha before sending another reset link.</div>';
                }
            }

            const formData = new FormData(form);
            const data = Object.fromEntries(formData);

            // Include captcha response when required
            if (attemptCount >= 2) {
                data['h-captcha-response'] = hcaptcha.getResponse();
            }

            try {
                const response = await fetch(`${API_BASE}/forgot-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (response.ok) {
                    messageEl.innerHTML = `<div class="message success">${result.message}</div>`;
                    form.reset();
                    if (attemptCount >= 2) hcaptcha.reset();

                    // Next steps info
                    setTimeout(() => {
                        messageEl.innerHTML += `
                            <div class="message success">
                                <strong>Next Steps:</strong><br>
                                1. Check your email inbox<br>
                                2. Click the reset link (expires in 5 minutes)<br>
                                3. Enter your new password
                            </div>
                        `;
                    }, 500);
                } else {
                    messageEl.innerHTML = `<div class="message error">${result.error}</div>`;
                    // Keep captcha visible if server requires it
                    if (/captcha/i.test(result.error)) {
                        captchaContainer.classList.remove('hidden');
                    }
                }
            } catch (err) {
                messageEl.innerHTML = `<div class="message error">Network error. Please try again.</div>`;
            }
        });
    </script>
</body>
</html>