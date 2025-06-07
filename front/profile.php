<?php 
require '../config_default.php';
session_start();

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
    <title>Edit Profile - SSSD Project</title>
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
        
        .nav-links {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .nav-links a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background-color 0.3s;
        }
        
        .nav-links a:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        
        .container {
            max-width: 800px;
            margin: 2rem auto;
            padding: 0 20px;
        }
        
        .profile-header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        }
        
        .profile-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 3rem;
            color: white;
            font-weight: bold;
        }
        
        .profile-header h2 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2rem;
        }
        
        .profile-header p {
            color: #666;
            font-size: 1.1rem;
        }
        
        .form-grid {
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
            padding: 12px 15px;
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
        
        .form-group input:disabled {
            background-color: #f8f9fa;
            color: #6c757d;
            cursor: not-allowed;
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            width: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
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
        
        .info-box {
            background: linear-gradient(45deg, #e3f2fd, #f3e5f5);
            border: 2px solid #bbdefb;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 20px;
            color: #1565c0;
            font-size: 14px;
        }
        
        .security-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            margin-bottom: 15px;
        }
        
        .security-item.enabled {
            border-left: 4px solid #28a745;
        }
        
        .security-item.disabled {
            border-left: 4px solid #dc3545;
        }
        
        .badge {
            padding: 6px 12px;
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
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .btn-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        .btn-group .btn {
            width: auto;
            flex: 1;
        }
        
        .readonly-field {
            background-color: #f8f9fa;
            color: #6c757d;
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>👤 Edit Profile</h1>
        <div class="nav-links">
            <a href="dashboard.php">← Dashboard</a>
            <a href="#" onclick="logout()">Logout</a>
        </div>
    </nav>

    <div class="container">
        <!-- Profile Header -->
        <div class="profile-header">
            <div class="profile-avatar" id="avatarIcon">U</div>
            <h2 id="profileName">Loading...</h2>
            <p id="profileEmail">Loading profile information...</p>
        </div>

        <div class="form-grid">
            <!-- Personal Information -->
            <div class="card">
                <h3><span class="card-icon">👤</span> Personal Information</h3>
                
                <div class="info-box">
                    <strong>Note:</strong> Some fields like username and email cannot be changed for security reasons. Contact support if you need to update these fields.
                </div>
                
                <form id="personalInfoForm">
                    <div class="form-group">
                        <label for="full_name">Full Name</label>
                        <input type="text" id="full_name" name="full_name" placeholder="Enter your full name" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" class="readonly-field" disabled>
                        <small style="color: #666; font-size: 12px;">Username cannot be changed</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" class="readonly-field" disabled>
                        <small style="color: #666; font-size: 12px;">Email cannot be changed</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="phone_number">Phone Number</label>
                        <input type="tel" id="phone_number" name="phone_number" placeholder="+38761234567" required>
                    </div>
                    
                    <button type="submit" class="btn" id="updatePersonalBtn">
                        Update Personal Information
                    </button>
                    
                    <div id="personalInfoMessage"></div>
                </form>
            </div>

            <!-- Security Settings -->
            <div class="card">
                <h3><span class="card-icon">🔐</span> Security Settings</h3>
                
                <div class="security-item" id="emailVerificationStatus">
                    <div>
                        <strong>Email Verification</strong>
                        <br><small>Your email address is verified</small>
                    </div>
                    <span class="badge badge-success">✅ Verified</span>
                </div>
                
                <div class="security-item" id="twoFactorStatus">
                    <div>
                        <strong>Two-Factor Authentication</strong>
                        <br><small id="twoFactorDescription">Loading...</small>
                    </div>
                    <span class="badge" id="twoFactorBadge">Loading...</span>
                </div>
                
                <div class="security-item">
                    <div>
                        <strong>Password</strong>
                        <br><small>Last changed: Loading...</small>
                    </div>
                    <span class="badge badge-success">🔒 Secure</span>
                </div>
                
                <div class="btn-group">
                    <button class="btn btn-secondary" onclick="window.location.href='dashboard.php'">
                        Security Dashboard
                    </button>
                </div>
            </div>

            <!-- Account Activity -->
            <div class="card">
                <h3><span class="card-icon">📊</span> Account Activity</h3>
                
                <div id="accountActivity">
                    <p>Loading account activity...</p>
                </div>
                
                <div class="btn-group">
                    <button class="btn btn-secondary" onclick="downloadAccountData()">
                        Download Data
                    </button>
                </div>
            </div>

            <!-- Danger Zone -->
            <div class="card">
                <h3><span class="card-icon">⚠️</span> Danger Zone</h3>
                
                <div class="info-box" style="background: linear-gradient(45deg, #fff3cd, #ffeaa7); border-color: #ffc107;">
                    <strong>Warning:</strong> These actions are permanent and cannot be undone.
                </div>
                
                <div class="form-group">
                    <label>Account Deactivation</label>
                    <p style="color: #666; font-size: 14px; margin-bottom: 15px;">
                        Temporarily disable your account. You can reactivate it by logging in again.
                    </p>
                    <button class="btn btn-secondary" onclick="deactivateAccount()">
                        Deactivate Account
                    </button>
                </div>
                
                <div class="form-group">
                    <label>Account Deletion</label>
                    <p style="color: #666; font-size: 14px; margin-bottom: 15px;">
                        Permanently delete your account and all associated data. This action cannot be undone.
                    </p>
                    <button class="btn btn-danger" onclick="deleteAccount()">
                        Delete Account
                    </button>
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

        // Load user profile data
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
                    
                    // Update profile header
                    document.getElementById('avatarIcon').textContent = user.full_name.charAt(0).toUpperCase();
                    document.getElementById('profileName').textContent = user.full_name;
                    document.getElementById('profileEmail').textContent = user.email;
                    
                    // Populate form fields
                    document.getElementById('full_name').value = user.full_name;
                    document.getElementById('username').value = user.username;
                    document.getElementById('email').value = user.email;
                    document.getElementById('phone_number').value = user.phone_number || '';
                    
                    // Update security status
                    updateSecurityStatus(user);
                    updateAccountActivity(user);
                    
                } else {
                    // Token expired or invalid
                    logout();
                }
            } catch (error) {
                console.error('Error loading profile:', error);
                showMessage('personalInfoMessage', 'Error loading profile data', 'error');
            }
        }

        // Update security status display
        function updateSecurityStatus(user) {
            const twoFactorStatus = document.getElementById('twoFactorStatus');
            const twoFactorBadge = document.getElementById('twoFactorBadge');
            const twoFactorDescription = document.getElementById('twoFactorDescription');
            
            if (user.two_fa_enabled) {
                twoFactorStatus.className = 'security-item enabled';
                twoFactorBadge.className = 'badge badge-success';
                twoFactorBadge.textContent = '✅ Enabled';
                twoFactorDescription.textContent = 'Your account is protected with 2FA';
            } else {
                twoFactorStatus.className = 'security-item disabled';
                twoFactorBadge.className = 'badge badge-warning';
                twoFactorBadge.textContent = '⚠️ Disabled';
                twoFactorDescription.textContent = 'Enable 2FA for better security';
            }
        }

        // Update account activity display
        function updateAccountActivity(user) {
            const activityHtml = `
                <div class="security-item">
                    <div>
                        <strong>Account Created</strong>
                        <br><small>${new Date(user.created_at).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                        })}</small>
                    </div>
                    <span class="badge badge-success">Active</span>
                </div>
                <div class="security-item">
                    <div>
                        <strong>Last Login</strong>
                        <br><small>Current session</small>
                    </div>
                    <span class="badge badge-success">Now</span>
                </div>
            `;
            document.getElementById('accountActivity').innerHTML = activityHtml;
        }

        // Personal information form handler
        document.getElementById('personalInfoForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);
            const submitBtn = document.getElementById('updatePersonalBtn');
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="loading"></span> Updating...';

            try {
                const response = await fetch(`${API_BASE}/user/update-profile`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${userToken}`
                    },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (response.ok) {
                    showMessage('personalInfoMessage', 'Profile updated successfully!', 'success');
                    // Update profile header
                    document.getElementById('profileName').textContent = data.full_name;
                    document.getElementById('avatarIcon').textContent = data.full_name.charAt(0).toUpperCase();
                } else {
                    showMessage('personalInfoMessage', result.error || 'Error updating profile', 'error');
                }
            } catch (error) {
                console.error('Error updating profile:', error);
                showMessage('personalInfoMessage', 'Network error occurred', 'error');
            } finally {
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Update Personal Information';
            }
        });

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

        function deactivateAccount() {
            if (confirm('Are you sure you want to deactivate your account? You can reactivate it by logging in again.')) {
                alert('Account deactivation feature will be implemented with additional security measures.');
            }
        }

        function deleteAccount() {
            const confirmation = prompt('To delete your account, type "DELETE" in all caps:');
            if (confirmation === 'DELETE') {
                if (confirm('This will permanently delete your account and all data. This action cannot be undone. Are you absolutely sure?')) {
                    alert('Account deletion feature will be implemented with additional security measures and verification steps.');
                }
            } else if (confirmation !== null) {
                alert('Account deletion cancelled. You must type "DELETE" exactly as shown.');
            }
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

        // Load profile on page load
        loadUserProfile();
    </script>
</body>
</html>