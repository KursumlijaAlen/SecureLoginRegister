<?php

namespace Sssd;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Flight;

class Middleware {
    
    public static function requireAuth() {
        $authHeader = Flight::request()->getHeader('Authorization');
        
        if (!$authHeader || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            Flight::json(['error' => 'Authorization token required'], 401);
            return false;
        }

        $token = $matches[1];
        
        try {
            $decoded = JWT::decode($token, new Key(JWT_SECRET, 'HS256'));
            
            Flight::set('user_id', $decoded->user_id);
            
            return true;
        } catch (Exception $e) {
            Flight::json(['error' => 'Invalid or expired token'], 401);
            return false;
        }
    }

    public static function cors() {
        if (Flight::request()->method === 'OPTIONS') {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
            header('Access-Control-Max-Age: 86400');
            http_response_code(200);
            exit();
        }

        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization');
    }

    public static function rateLimit($identifier, $maxAttempts = 5, $timeWindow = 3600) {
        $cacheFile = sys_get_temp_dir() . '/rate_limit_' . md5($identifier);
        $attempts = [];
        
        if (file_exists($cacheFile)) {
            $attempts = json_decode(file_get_contents($cacheFile), true) ?: [];
        }
        
        $cutoff = time() - $timeWindow;
        $attempts = array_filter($attempts, function($timestamp) use ($cutoff) {
            return $timestamp > $cutoff;
        });
        
        if (count($attempts) >= $maxAttempts) {
            Flight::json(['error' => 'Rate limit exceeded. Please try again later.'], 429);
            return false;
        }
        
        $attempts[] = time();
        file_put_contents($cacheFile, json_encode($attempts));
        
        return true;
    }
}