<?php
// Weak hash (flagged unless a comparison operand, which TypeJuggling handles).
$a = md5($data);                        // BUG: weak hash
$b = sha1($data);                       // BUG
$c = crypt($pw);                        // BUG
if (md5($x) === $stored) {}             // safe here: comparison operand (type-juggling's domain)

// LDAP bind without a password.
ldap_bind($conn);                       // BUG: no password
ldap_bind($conn, "", "");               // BUG: empty password
ldap_bind($conn, $dn, $password);       // safe: password provided

// Permissive CORS via raw header.
header("Access-Control-Allow-Origin: *");   // BUG
header("Access-Control-Allow-Origin: *evil*"); // safe: not a bare wildcard
header("X-Frame-Options: DENY");            // safe: different header
