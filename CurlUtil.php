<?php

namespace Sssd;

class CurlUtil {
    private static function sendRequest($method, $url, $data = null, $headers = []) {
        $curl = curl_init();
        
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => 30
        ];
        
        if ($data) {
            if (is_array($data)) {
                $data = json_encode($data);
            }
            $options[CURLOPT_POSTFIELDS] = $data;
        }
        
        curl_setopt_array($curl, $options);
        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        
        if (curl_errno($curl)) {
            $error = curl_error($curl);
            curl_close($curl);
            throw new Exception('cURL Error: ' . $error);
        }
        
        curl_close($curl);
        return ['response' => $response, 'http_code' => $httpCode];
    }

    public static function get($url, $headers = []) {
        return self::sendRequest('GET', $url, null, $headers);
    }

    public static function post($url, $data = null, $headers = []) {
        return self::sendRequest('POST', $url, $data, $headers);
    }

    public static function put($url, $data = null, $headers = []) {
        return self::sendRequest('PUT', $url, $data, $headers);
    }

    public static function patch($url, $data = null, $headers = []) {
        return self::sendRequest('PATCH', $url, $data, $headers);
    }

    public static function delete($url, $headers = []) {
        return self::sendRequest('DELETE', $url, null, $headers);
    }
}