<?php
function rsa_sha1_sign($policy, $private_key_filename)
{
    $signature = "";
    // load the private key
    $fp = fopen($private_key_filename, "r");
    $priv_key = fread($fp, 8192);
    fclose($fp);
    $pkeyid = openssl_get_privatekey($priv_key);

    // compute signature
    openssl_sign($policy, $signature, $pkeyid);
    // free the key from memory
    openssl_free_key($pkeyid);
    return $signature;
}
function url_safe_base64_encode($value)
{
    $encoded = base64_encode($value);
    // replace unsafe characters +, = and / with the safe characters -, _ and ~
    return str_replace(
        array('+', '=', '/'),
        array('-', '_', '~'),
        $encoded
    );
}
function url_safe_base64_encode1($value)
{
    $encoded = base64_encode($value);
    // replace unsafe characters +, = and / with the safe characters -, _ and ~
    return  $encoded;
}

function create_stream_name($stream, $policy, $signature, $key_pair_id, $expires)
{
    $path = "";
    $result = $stream;
    $separator = strpos($stream, '?') == FALSE ? '?' : '&';
    if ($expires) {
        $result .= $path . $separator . "Expires=" . $expires . "&Signature=" . $signature . "&Key-Pair-Id=" . $key_pair_id;
    } else {
        $result .= $path . $separator . "Policy=" . $policy . "&Signature=" . $signature . "&Key-Pair-Id=" . $key_pair_id;
    }
    return str_replace('\n', '', $result);
}

function encode_query_params($stream_name)
{
    return str_replace(
        array('?', '=', '&'),
        array('?', '=', '&'),
        $stream_name
    );
}

function get_custom_policy_stream_name($url_path, $private_key_filename, $key_pair_id, $policy)
{
    $encoded_policy = url_safe_base64_encode($policy);
    $signature = rsa_sha1_sign($policy, $private_key_filename);
    $encoded_signature = url_safe_base64_encode($signature);
    $stream_name = create_stream_name($url_path, $encoded_policy, $encoded_signature, $key_pair_id, null);
    return encode_query_params($stream_name);
}

$private_key_filename = '/root/sign/pri_signtest.myskcdn.net.pem';
$key_pair_id = 'pub_signtest.myskcdn.net';
$url_path = 'http://signtest.myskcdn.net/skcdn.mp4';
$expires = time() + 21600; // 1 day from now
$client_ip = "0.0.0.0/0";
$policy =
    '{' .
    '"Statement":[' .
    '{' .
    '"Resource":"http*://signtest.myskcdn.net/*",' .
    '"Condition":{' .
    '"DateLessThan":{"AWS:EpochTime":' . $expires . '},' .
    '"IpAddress":{"AWS:SourceIp":"' . $client_ip . '"}' .
    '}' .
    '}' .
    ']' .
    '}';

$custom_policy_stream_name = get_custom_policy_stream_name($url_path, $private_key_filename, $key_pair_id, $policy);
echo $custom_policy_stream_name;
