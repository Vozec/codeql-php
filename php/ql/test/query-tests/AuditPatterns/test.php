<?php
// Weak hash (flagged unless a comparison operand, which TypeJuggling handles).
$a = md5($data);                        // BUG: weak hash
$b = sha1($data);                       // BUG
$c = crypt($pw);                        // BUG
if (md5($x) === $stored) {}             // safe here: comparison operand (type-juggling's domain)

// LDAP bind without a password.
ldap_bind($conn);                       // BUG: anonymous bind (no password)
ldap_bind($conn, "cn=admin");           // BUG: no password argument
ldap_bind($conn, $dn, $password);       // safe: password provided

// Laravel active debug code (APP_DEBUG enabled).
config(['app.debug' => 'true']);        // BUG: debug enabled
putenv("APP_DEBUG=true");               // BUG
config(['app.debug' => 'false']);       // safe: disabled

// Permissive CORS via raw header.
header("Access-Control-Allow-Origin: *");   // BUG
header("Access-Control-Allow-Origin: *evil*"); // safe: not a bare wildcard
header("X-Frame-Options: DENY");            // safe: different header

// Weak SHA-224 family (too short); strong algos are safe.
hash('sha224', $data);                  // BUG
hash('sha512/224', $data);              // BUG
hash('sha384', $data);                  // safe: strong algo
