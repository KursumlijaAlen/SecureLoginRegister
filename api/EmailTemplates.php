<?php

namespace Sssd;

class EmailTemplates {
    
    public static function welcomeEmail($fullName, $verificationLink) {
        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Welcome to SSSD Project</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #007bff; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
                .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Welcome to SSSD Project!</h1>
                </div>
                <div class='content'>
                    <p>Dear {$fullName},</p>
                    <p>Thank you for registering with our secure authentication system. To complete your registration, please verify your email address by clicking the button below:</p>
                    <p style='text-align: center; margin: 30px 0;'>
                        <a href='{$verificationLink}' class='button'>Verify Email Address</a>
                    </p>
                    <p>This verification link will expire in 24 hours. If you didn't create this account, please ignore this email.</p>
                    <p>For security reasons, you won't be able to log in until your email is verified.</p>
                </div>
                <div class='footer'>
                    <p>SSSD Project - Secure Software System Development</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>";
    }
    
    public static function passwordResetEmail($fullName, $resetLink) {
        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Password Reset Request</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Password Reset Request</h1>
                </div>
                <div class='content'>
                    <p>Dear {$fullName},</p>
                    <p>You have requested to reset your password. Click the button below to set a new password:</p>
                    <p style='text-align: center; margin: 30px 0;'>
                        <a href='{$resetLink}' class='button'>Reset Password</a>
                    </p>
                    <div class='warning'>
                        <strong>Security Notice:</strong>
                        <ul>
                            <li>This link will expire in 5 minutes</li>
                            <li>It can only be used once</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                        </ul>
                    </div>
                </div>
                <div class='footer'>
                    <p>SSSD Project - Secure Software System Development</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>";
    }
    
    public static function passwordChangedEmail($fullName) {
        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Password Changed Successfully</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #28a745; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .alert { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Password Changed Successfully</h1>
                </div>
                <div class='content'>
                    <p>Dear {$fullName},</p>
                    <p>Your password has been successfully changed.</p>
                    <div class='alert'>
                        <strong>Security Information:</strong>
                        <p>If you did not make this change, please contact our support team immediately and change your password again.</p>
                    </div>
                    <p>For your security, we recommend:</p>
                    <ul>
                        <li>Using a unique password for this account</li>
                        <li>Enabling two-factor authentication</li>
                        <li>Regularly reviewing your account activity</li>
                    </ul>
                </div>
                <div class='footer'>
                    <p>SSSD Project - Secure Software System Development</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>";
    }
}