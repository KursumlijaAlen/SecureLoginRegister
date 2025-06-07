<?php

require 'vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

function send_sms($phone, $code) 
{
    $curl = curl_init();
    $API_KEY = $_ENV['API_KEY'];

    if (!$API_KEY) {
        die("Error: API key is missing. Please check your .env file.");
    }

    $data = [
        "messages" => [
            [
                "from" => "InfoSMS",
                "destinations" => [
                    [
                        "to" => $phone
                    ]
                ],
                "text" => "Your verification code is: $code"
            ]
        ]
    ];

    curl_setopt_array($curl, array(
        CURLOPT_URL => 'https://3844kj.api.infobip.com/sms/2/text/advanced',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_HTTPHEADER => array(
            'Authorization: App ' . $API_KEY,
            'Content-Type: application/json',
            'Accept: application/json'
        ),
    ));

    $response = curl_exec($curl);
    
    if (curl_errno($curl)) {
        echo 'Error:' . curl_error($curl);
    } else {
        echo 'Response: ' . $response;
    }

    curl_close($curl);
}

send_sms("38762122378", "555333"); 

?>
