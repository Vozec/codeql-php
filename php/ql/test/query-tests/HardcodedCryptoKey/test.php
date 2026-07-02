<?php
$key = "hardcoded_secret_123";
openssl_encrypt($data, "aes-256-cbc", $key);       // BUG
hash_hmac("sha256", $msg, "inline_key");           // BUG
openssl_encrypt($data, "aes-256-cbc", $_GET['k']); // ok: from input, not hardcoded
