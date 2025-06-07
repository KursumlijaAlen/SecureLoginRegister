<?php

namespace Sssd;

class SMSVerification {
    
    public static function sendVerificationCode($phoneNumber) {
        $code = sprintf('%06d', random_int(100000, 999999));
        
        $_SESSION['sms_code'] = $code;
        $_SESSION['sms_code_expires'] = time() + 300; 
        $_SESSION['sms_phone'] = $phoneNumber;
        
        $controller = new Controller();
        return $controller->sendSMS($phoneNumber, $code);
    }
    
    public static function verifyCode($inputCode) {
        if (empty($_SESSION['sms_code']) || empty($_SESSION['sms_code_expires'])) {
            return false;
        }
        
        if (time() > $_SESSION['sms_code_expires']) {
            unset($_SESSION['sms_code'], $_SESSION['sms_code_expires'], $_SESSION['sms_phone']);
            return false;
        }
        
        $isValid = $_SESSION['sms_code'] === $inputCode;
        
        if ($isValid) {
            unset($_SESSION['sms_code'], $_SESSION['sms_code_expires'], $_SESSION['sms_phone']);
        }
        
        return $isValid;
    }
}
