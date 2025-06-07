<?php
require __DIR__. '/../vendor/autoload.php';
require __DIR__. '/../config_default.php';

use Sssd\Controller;
use Sssd\Database;

session_start();

$db = Database::getInstance();

Flight::post('/register', [Controller::class, 'register']);
Flight::post('/login', [Controller::class, 'login']);
Flight::post('/generate-otp', [Controller::class, 'generateOtp']);
Flight::post('/verify-otp', [Controller::class, 'verifyOtp']);
Flight::route('GET /user/2fa-methods', [Controller::class, 'get2FAMethods']);
Flight::post('/user/send-2fa-code', [Controller::class, 'send2FACode']);
Flight::post('/user/setup-2fa', [Controller::class, 'setup2FAMethod']);
Flight::post('/user/remove-2fa', [Controller::class, 'remove2FAMethod']);
Flight::post('/forgot-password', [Controller::class, 'forgotPassword']);
Flight::post('/reset-password', [Controller::class, 'resetPassword']);
Flight::route('GET /verify-email/@token', [Controller::class, 'verifyEmail']);
Flight::post('/resend-verification', [Controller::class, 'resendVerification']);
Flight::route('GET /user/profile', [Controller::class, 'getUserProfile']);
Flight::post('/user/change-password', [Controller::class, 'changePassword']);
Flight::post('/user/update-2fa', [Controller::class, 'update2FA']);
Flight::post('/user/update-profile', [Controller::class, 'updateProfile']);
Flight::post('/logout', [Controller::class, 'logout']);
Flight::route('GET /google-login',    [Controller::class, 'googleLogin']);
Flight::route('GET /google-callback', [Controller::class, 'googleCallback']);

Flight::route('GET /', function(){
    echo 'API is online';
});

Flight::before('start', function () {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
});

Flight::start();