<?php
require '../config_default.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = [
        'secret' => HCAPTCHA_SERVER_SECRET,
        'response' => $_POST['h-captcha-response']
    ];

    $verify = curl_init();
    curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
    curl_setopt($verify, CURLOPT_POST, true);
    curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($verify);
    curl_close($verify);

    $responseData = json_decode($response);

    if ($responseData->success) {
        echo "You passed the captcha!";
    } else {
        echo "You did NOT pass the captcha!";
    }
}
?>