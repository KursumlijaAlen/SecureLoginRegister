<?php 
require '../config_default.php';
session_start();

// Check if user is logged in
if (empty($_SESSION['user_id']) && empty($_SESSION['token'])) {
    header('Location: login.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SSSD Project</title>
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
        }
        
        .navbar {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: white;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
        }
        
        .navbar h1 {
            font-size: 1.5rem;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 20px;
        }
        
        .welcome-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        }
        
        .welcome-card h2 {
            color: #333;
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .welcome-card .user-info {
            background: linear-gradient(45deg, #4ecdc4, #44a08d);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-top: 20px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h3 {
            color: #333;
            font-size: 1.4rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-icon {
            font-size: 1.5rem;
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
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
        }
        
        .btn-small {
            padding: 8px 16px;
            font-size: 12px;
        }
        
        .security-status {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .status-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .status-enabled {
            border-left: 4px solid #28a745;
        }
        
        .status-disabled {
            border-left: 4px solid #dc3545;
        }
        
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
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
        
        .hidden {
            display: none;
        }
        
        .recovery-codes {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-top: 15px;
        }
        
        .recovery-codes h4 {
            margin-bottom: 15px;
            color: #495057;
        }
        
        .codes-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            font-family: monospace;
            font-size: 14px;
        }
        
        .code-item {
            background: white;
            padding: 8px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #ddd;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            backdrop-filter: blur(5px);
        }

        .modal.hidden {
            display: none;
        }

        .modal:not(.hidden) {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            border-radius: 20px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }

        .modal-header {
            padding: 20px 30px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
            color: #333;
        }

        .close {
            font-size: 2rem;
            cursor: pointer;
            color: #999;
            transition: color 0.3s;
        }

        .close:hover {
            color: #333;
        }

        .modal-body {
            padding: 30px;
        }

        .method-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }

        .method-card {
            background: #f8f9fa;
            border: 2px solid #e1e5e9;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .method-card:hover {
            border-color: #667eea;
            background: linear-gradient(45deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            transform: translateY(-3px);
        }

        .method-card .method-icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }

        .method-card h4 {
            margin: 0 0 10px 0;
            color: #333;
        }

        .method-card p {
            margin: 0;
            color: #666;
            font-size: 0.9rem;
        }

        .setup-form {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin: 20px 0;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }

        .twofa-method-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
            margin: 15px 0;
            border-left: 4px solid #28a745;
        }

        .twofa-method-item.disabled {
            border-left-color: #dc3545;
            opacity: 0.7;
        }

        .method-info h4 {
            margin: 0 0 5px 0;
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .method-info p {
            margin: 0;
            color: #666;
            font-size: 0.9rem;
        }

        .method-actions {
            display: flex;
            gap: 10px;
        }

        .btn-small {
            padding: 6px 12px;
            font-size: 0.8rem;
        }

        .backup-codes-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            color: #856404;
        }

        .backup-codes-list {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin: 20px 0;
            font-family: monospace;
        }

        .backup-code {
            background: white;
            border: 1px solid #ddd;
            padding: 10px;
            text-align: center;
            border-radius: 6px;
            font-weight: bold;
            letter-spacing: 1px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🔐 SSSD Dashboard</h1>
        <div class="user-menu">
            <span id="userGreeting">Loading...</span>
            <button class="btn btn-danger btn-small" onclick="logout()">Logout</button>
        </div>
    </nav>

    <div class="container">
        <!-- Welcome Section -->
        <div class="welcome-card">
            <h2>Welcome to Your Dashboard</h2>
            <p>Manage your account security and settings</p>
            <div class="user-info" id="userInfo">
                <p>Loading user information...</p>
            </div>
        </div>

        <div class="dashboard-grid">
            <!-- Security Settings -->
            <div class="card">
                <h3><span class="card-icon">🔐</span> Two-Factor Authentication</h3>
                
                <div id="twoFactorMethods">
                    <p>Loading 2FA methods...</p>
                </div>
                
                <div class="btn-group" style="margin-top: 20px;">
                    <button class="btn" onclick="showAddMethodModal()">+ Add 2FA Method</button>
                    <button class="btn btn-secondary" style="margin-top: 8px;" onclick="generateNewBackupCodes()">New Backup Codes</button>
                </div>
                
                <div id="twoFactorMessage"></div>
            </div>

            <!-- Add 2FA Method Modal -->
            <div id="addMethodModal" class="modal hidden">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Add 2FA Method</h3>
                        <span class="close" onclick="closeAddMethodModal()">&times;</span>
                    </div>
                    <div class="modal-body">
                        <div class="method-options">
                            <div class="method-card" onclick="setupMethod('totp')">
                                <div class="method-icon">📱</div>
                                <h4>Authenticator App</h4>
                                <p>Google Authenticator, Authy, etc.</p>
                            </div>
                            
                            <div class="method-card" onclick="setupMethod('sms')">
                                <div class="method-icon">📞</div>
                                <h4>SMS Verification</h4>
                                <p>Receive codes via text message</p>
                            </div>
                            
                            <div class="method-card" onclick="setupMethod('email')">
                                <div class="method-icon">📧</div>
                                <h4>Email Verification</h4>
                                <p>Receive codes via email</p>
                            </div>
                            
                            <div class="method-card" onclick="setupMethod('backup')">
                                <div class="method-icon">🔑</div>
                                <h4>Backup Codes</h4>
                                <p>One-time recovery codes</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Setup Forms (initially hidden) -->
            <div id="setupForms" class="hidden">
                <!-- TOTP Setup -->
                <div id="totpSetup" class="setup-form hidden">
                    <h3>📱 Set Up Authenticator App</h3>
                    <div id="totpQRCode"></div>
                    <form id="totpVerifyForm">
                        <div class="form-group">
                            <label>Enter code from your app to verify:</label>
                            <input type="text" name="otp" maxlength="6" placeholder="000000" required>
                        </div>
                        <button type="submit" class="btn">Verify & Enable</button>
                    </form>
                </div>
                
                <!-- SMS Setup -->
                <div id="smsSetup" class="setup-form hidden">
                    <h3>📞 Set Up SMS Verification</h3>
                    <form id="smsSetupForm">
                        <div class="form-group">
                            <label>Mobile Phone Number:</label>
                            <input type="tel" name="phone_number" placeholder="+38761234567" required>
                            <small>Must be a valid mobile number</small>
                        </div>
                        <button type="submit" class="btn">Enable SMS 2FA</button>
                    </form>
                </div>
                
                <!-- Email Setup -->
                <div id="emailSetup" class="setup-form hidden">
                    <h3>📧 Set Up Email Verification</h3>
                    <form id="emailSetupForm">
                        <div class="form-group">
                            <label>Email Address:</label>
                            <input type="email" name="email_address" placeholder="your-email@example.com" required>
                            <small>Can use a different email than your login email</small>
                        </div>
                        <button type="submit" class="btn">Enable Email 2FA</button>
                    </form>
                </div>
                
                <!-- Backup Codes Display -->
                <div id="backupCodesDisplay" class="setup-form hidden">
                    <h3>🔑 Your Backup Codes</h3>
                    <div class="backup-codes-warning">
                        <strong>⚠️ Important:</strong> Save these codes securely! Each can only be used once.
                    </div>
                    <div id="backupCodesList"></div>
                    <div class="btn-group">
                        <button class="btn" onclick="downloadBackupCodes()">Download Codes</button>
                        <button class="btn btn-secondary" onclick="printBackupCodes()">Print Codes</button>
                    </div>
                </div>
            </div>

            <!-- Change Password -->
            <div class="card">
                <h3><span class="card-icon">🔑</span> Change Password</h3>
                <form id="changePasswordForm">
                    <div class="form-group">
                        <label>Current Password:</label>
                        <input type="password" name="current_password" required>
                    </div>
                    <div class="form-group">
                        <label>New Password:</label>
                        <input type="password" name="new_password" required minlength="8">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password:</label>
                        <input type="password" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn">Update Password</button>
                </form>
                <div id="passwordMessage"></div>
            </div>

            <!-- Account Information -->
            <div class="card">
                <h3><span class="card-icon">👤</span> Account Information</h3>
                <div id="accountInfo">
                    <p>Loading account details...</p>
                </div>
            </div>

            <div class="card">
                <h3><span class="card-icon">🔒</span> Security Status</h3>
                <div id="securityStatus">
                    <p>Loading security status…</p>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="card">
                <h3><span class="card-icon">⚡</span> Quick Actions</h3>
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <button class="btn" onclick="window.location.href='profile.php'">Edit Profile</button>
                    <button class="btn" onclick="downloadAccountData()">Download Account Data</button>
                    <button class="btn btn-danger" onclick="confirmDeleteAccount()">Delete Account</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = '../api';
        let userToken = sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token');

        // Check authentication
        if (!userToken) {
           window.location.href = 'login.php';
        }

        // Load user profile
        async function loadUserProfile() {
            try {
                const response = await fetch(`${API_BASE}/user/profile`, {
                    headers: {
                        'Authorization': `Bearer ${userToken}`
                    }
                });

                if (response.ok) {
                    const result = await response.json();
                    const user = result.user;
                    
                    // Update welcome message
                    document.getElementById('userGreeting').textContent = `Hello, ${user.full_name.split(' ')[0]}!`;
                    
                    // Update user info card
                    document.getElementById('userInfo').innerHTML = `
                        <h4>Account Details</h4>
                        <p><strong>Name:</strong> ${user.full_name}</p>
                        <p><strong>Username:</strong> @${user.username}</p>
                        <p><strong>Email:</strong> ${user.email}</p>
                        <p><strong>Member since:</strong> ${new Date(user.created_at).toLocaleDateString()}</p>
                    `;

                    // Update account info section
                    document.getElementById('accountInfo').innerHTML = `
                        <div class="status-item">
                            <span>Email Status</span>
                            <span class="badge badge-success">Verified ✓</span>
                        </div>
                        <div class="status-item">
                            <span>Account Type</span>
                            <span class="badge badge-success">Standard User</span>
                        </div>
                        <div class="status-item">
                            <span>Last Login</span>
                            <span>${new Date().toLocaleDateString()}</span>
                        </div>
                    `;

                    // Update security status
                    const securityHtml = `
                        <div class="status-item ${user.two_fa_enabled ? 'status-enabled' : 'status-disabled'}">
                            <span>Two-Factor Authentication</span>
                            <span class="badge ${user.two_fa_enabled ? 'badge-success' : 'badge-warning'}">
                                ${user.two_fa_enabled ? 'Enabled ✓' : 'Disabled ⚠️'}
                            </span>
                        </div>
                        <div class="status-item status-enabled">
                            <span>Email Verification</span>
                            <span class="badge badge-success">Verified ✓</span>
                        </div>
                        <div class="status-item status-enabled">
                            <span>Password Security</span>
                            <span class="badge badge-success">Strong ✓</span>
                        </div>
                    `;
                    document.getElementById('securityStatus').innerHTML = securityHtml;
                } else {
                    // Token expired or invalid
                    logout();
                }
            } catch (error) {
                console.error('Error loading profile:', error);
                showMessage('passwordMessage', 'Error loading profile data', 'error');
            }
        }

        // Change password form handler
        document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            if (data.new_password !== data.confirm_password) {
                showMessage('passwordMessage', 'Passwords do not match!', 'error');
                return;
            }

            try {
                const response = await fetch(`${API_BASE}/user/change-password`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({
                        current_password: data.current_password,
                        new_password: data.new_password
                    })
                });

                const result = await response.json();

                if (response.ok) {
                    showMessage('passwordMessage', 'Password changed successfully!', 'success');
                    e.target.reset();
                } else {
                    showMessage('passwordMessage', result.error, 'error');
                }
            } catch (error) {
                showMessage('passwordMessage', 'Network error occurred', 'error');
            }
        });

        // Toggle sections
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            section.classList.toggle('hidden');
        }

        // Disable 2FA
        async function disable2FA() {
            if (!confirm('Are you sure you want to disable 2FA? This will make your account less secure.')) {
                return;
            }

            try {
                const response = await fetch(`${API_BASE}/user/update-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ action: 'disable' })
                });

                if (response.ok) {
                    alert('2FA has been disabled');
                    loadUserProfile(); // Refresh security status
                } else {
                    alert('Error disabling 2FA');
                }
            } catch (error) {
                alert('Network error occurred');
            }
        }

        // Generate recovery codes
        async function generateRecoveryCodes() {
            try {
                const response = await fetch(`${API_BASE}/user/update-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ action: 'generate_recovery' })
                });

                if (response.ok) {
                    const result = await response.json();
                    const codes = result.recovery_codes;
                    
                    const codesHtml = codes.map(code => 
                        `<div class="code-item">${code}</div>`
                    ).join('');
                    
                    document.getElementById('recoveryCodes').innerHTML = `
                        <div class="recovery-codes">
                            <h4>🔑 Recovery Codes</h4>
                            <p><strong>Important:</strong> Save these codes securely. Each can only be used once.</p>
                            <div class="codes-grid">${codesHtml}</div>
                            <button class="btn btn-small" onclick="downloadCodes('${codes.join('\\n')}')" style="margin-top: 15px;">
                                Download Codes
                            </button>
                        </div>
                    `;
                } else {
                    alert('Error generating recovery codes');
                }
            } catch (error) {
                alert('Network error occurred');
            }
        }

        // Download recovery codes
        function downloadCodes(codes) {
            const blob = new Blob([`SSSD Project - Recovery Codes\n\n${codes}\n\nKeep these codes safe and secure!`], 
                                 { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sssd-recovery-codes.txt';
            a.click();
            window.URL.revokeObjectURL(url);
        }

        // Utility functions
        function showMessage(elementId, message, type) {
            const element = document.getElementById(elementId);
            if (element) {
                element.innerHTML = `<div class="message ${type}">${message}</div>`;
                setTimeout(() => {
                    element.innerHTML = '';
                }, 5000);
            }
        }

        function downloadAccountData() {
            alert('Account data download feature will be implemented in future updates.');
        }

        function confirmDeleteAccount() {
            if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
                alert('Account deletion feature will be implemented with additional security measures.');
            }
        }

        
        async function load2FAMethods() {
            try {
                const response = await fetch(`${API_BASE}/user/2fa-methods`, {
                    headers: { 'Authorization': `Bearer ${userToken}` }
                });
                
                if (response.ok) {
                    const result = await response.json();
                    display2FAMethods(result.methods);
                } else {
                    show2FAMessage('Error loading 2FA methods', 'error');
                }
            } catch (error) {
                show2FAMessage('Network error loading 2FA methods', 'error');
            }
        }

        // Display 2FA methods
        function display2FAMethods(methods) {
            const container = document.getElementById('twoFactorMethods');
            
            if (methods.length === 0) {
                container.innerHTML = `
                    <div class="twofa-method-item disabled">
                        <div class="method-info">
                            <h4>⚠️ No 2FA Methods Enabled</h4>
                            <p>Add at least one 2FA method to secure your account</p>
                        </div>
                    </div>
                `;
                return;
            }
            
            const methodsHTML = methods.map(method => `
                <div class="twofa-method-item">
                    <div class="method-info">
                        <h4>${method.icon} ${method.name}</h4>
                        <p>${method.description}</p>
                    </div>
                    <div class="method-actions">
                        <button class="btn btn-danger btn-small" onclick="remove2FAMethod('${method.type}')">
                            Remove
                        </button>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = methodsHTML;
        }

        // Show/hide modal
        function showAddMethodModal() {
            document.getElementById('addMethodModal').classList.remove('hidden');
        }

        function closeAddMethodModal() {
            document.getElementById('addMethodModal').classList.add('hidden');
            hideAllSetupForms();
        }

        // Setup different 2FA methods
        async function setupMethod(method) {
            closeAddMethodModal();

            if (method === 'sms') {
                return showSMSSetup();
            }
            if (method === 'email') {
                return showEmailSetup();
            }
            
            try {
                const response = await fetch(`${API_BASE}/user/setup-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ method: method })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    switch (method) {
                        case 'totp':
                            showTOTPSetup(result.qr_code_url, result.secret);
                            break;
                        case 'sms':
                            showSMSSetup();
                            break;
                        case 'email':
                            showEmailSetup();
                            break;
                        case 'backup':
                            showBackupCodes(result.codes);
                            break;
                    }
                } else {
                    show2FAMessage(result.error, 'error');
                }
            } catch (error) {
                show2FAMessage('Error setting up 2FA method', 'error');
            }
        }

        // Show setup forms
        function showTOTPSetup(qrCodeUrl, secret) {
            hideAllSetupForms();
            const setupDiv = document.getElementById('totpSetup');
            setupDiv.classList.remove('hidden');
            
            document.getElementById('totpQRCode').innerHTML = `
                <div style="text-align: center; margin: 20px 0;">
                    <img src="${qrCodeUrl}" alt="QR Code" style="max-width: 250px; border-radius: 10px;">
                    <p style="margin-top: 15px; font-size: 0.9rem; color: #666;">
                        Can't scan? Manual entry code: <br>
                        <code style="background: #f1f1f1; padding: 5px; border-radius: 4px;">${secret}</code>
                    </p>
                </div>
            `;
            
            document.getElementById('setupForms').classList.remove('hidden');
        }

        function showSMSSetup() {
            hideAllSetupForms();
            document.getElementById('smsSetup').classList.remove('hidden');
            document.getElementById('setupForms').classList.remove('hidden');
        }

        function showEmailSetup() {
            hideAllSetupForms();
            document.getElementById('emailSetup').classList.remove('hidden');
            document.getElementById('setupForms').classList.remove('hidden');
        }

        function showBackupCodes(codes) {
            hideAllSetupForms();
            const backupDiv = document.getElementById('backupCodesDisplay');
            const codesList = document.getElementById('backupCodesList');
            
            const codesHTML = codes.map(code => 
                `<div class="backup-code">${code}</div>`
            ).join('');
            
            codesList.innerHTML = `<div class="backup-codes-list">${codesHTML}</div>`;
            
            backupDiv.classList.remove('hidden');
            document.getElementById('setupForms').classList.remove('hidden');
            
            // Store codes for download/print
            window.currentBackupCodes = codes;
        }

        function hideAllSetupForms() {
            document.querySelectorAll('.setup-form').forEach(form => {
                form.classList.add('hidden');
            });
            document.getElementById('setupForms').classList.add('hidden');
        }

        // Form handlers
        document.getElementById('smsSetupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            
            try {
                const response = await fetch(`${API_BASE}/user/setup-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ method: 'sms', ...data })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    show2FAMessage('SMS 2FA enabled successfully!', 'success');
                    hideAllSetupForms();
                    load2FAMethods();
                } else {
                    show2FAMessage(result.error, 'error');
                }
            } catch (error) {
                show2FAMessage('Error enabling SMS 2FA', 'error');
            }
        });

        // **Email setup handler**  ← ADD THIS BLOCK
        document.getElementById('emailSetupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            
            try {
                const response = await fetch(`${API_BASE}/user/setup-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({
                        method:        'email',
                        email_address: data.email_address
                    })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    show2FAMessage('Email 2FA enabled successfully!', 'success');
                    hideAllSetupForms();
                    load2FAMethods();
                } else {
                    show2FAMessage(result.error, 'error');
                }
            } catch (error) {
                show2FAMessage('Error enabling Email 2FA', 'error');
            }
        });

                // TOTP verify handler
        document.getElementById('totpVerifyForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = e.target.otp.value.trim();
            if (!code) return show2FAMessage('Please enter the code from your app', 'error');

            try {
                const response = await fetch(`${API_BASE}/verify-otp`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ method: 'totp', otp: code })
                });
                const result = await response.json();

                if (response.ok) {
                    show2FAMessage('Authenticator App enabled!', 'success');
                    hideAllSetupForms();
                    load2FAMethods();
                } else {
                    show2FAMessage(result.error || 'Invalid code', 'error');
                }
            } catch (err) {
                show2FAMessage('Network error verifying code', 'error');
            }
        });


        // Remove 2FA method
        async function remove2FAMethod(method) {
            if (!confirm(`Are you sure you want to remove ${method.toUpperCase()} 2FA? You must have at least one 2FA method enabled.`)) {
                return;
            }
            
            try {
                const response = await fetch(`${API_BASE}/user/remove-2fa`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify({ method: method })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    show2FAMessage('2FA method removed successfully', 'success');
                    load2FAMethods();
                } else {
                    show2FAMessage(result.error, 'error');
                }
            } catch (error) {
                show2FAMessage('Error removing 2FA method', 'error');
            }
        }

        // Utility functions
        function show2FAMessage(message, type) {
            const messageEl = document.getElementById('twoFactorMessage');
            messageEl.innerHTML = `<div class="message ${type}">${message}</div>`;
            setTimeout(() => {
                messageEl.innerHTML = '';
            }, 5000);
        }

        function downloadBackupCodes() {
            if (!window.currentBackupCodes) return;
            
            const content = `SSSD Project - Backup Recovery Codes\n\n${window.currentBackupCodes.join('\n')}\n\nKeep these codes safe and secure!\nEach code can only be used once.`;
            const blob = new Blob([content], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sssd-backup-codes.txt';
            a.click();
            window.URL.revokeObjectURL(url);
        }

        function printBackupCodes() {
            if (!window.currentBackupCodes) return;
            
            const printWindow = window.open('', '_blank');
            printWindow.document.write(`
                <html>
                <head><title>SSSD Backup Codes</title></head>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>SSSD Project - Backup Recovery Codes</h2>
                    <p><strong>Keep these codes safe and secure!</strong></p>
                    <p>Each code can only be used once.</p>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 20px 0;">
                        ${window.currentBackupCodes.map(code => 
                            `<div style="border: 1px solid #ccc; padding: 10px; text-align: center; font-family: monospace; font-weight: bold;">${code}</div>`
                        ).join('')}
                    </div>
                </body>
                </html>
            `);
            printWindow.document.close();
            printWindow.print();
        }
        
        // Logout function
        async function logout() {
            try {
                await fetch(`${API_BASE}/logout`, { 
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${userToken}` }
                });
            } catch (error) {
                console.log('Logout request failed, but continuing...');
            }
            
            localStorage.removeItem('auth_token');
            sessionStorage.removeItem('auth_token');
            window.location.href = 'login.php';
        }

        // Load user profile on page load
        loadUserProfile();
        load2FAMethods();
    </script>
</body>
</html>