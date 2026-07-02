<?php
if (md5($input) == $stored) {}          // BUG: loose hash compare
if ($user_password == $db_password) {}  // BUG: secret-named var
if (hash('sha256',$x) != $sig) {}       // BUG: loose !=
if (md5($input) === $stored) {}         // ok: strict
if (hash_equals($a, $b)) {}             // ok: constant-time
if ($count == 5) {}                     // ok: not sensitive
