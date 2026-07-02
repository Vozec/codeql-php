<?php
eval($code);                 // eval-use
phpinfo();                   // phpinfo-use
unlink($f);                  // unlink-use
unserialize($data);          // unserialize-use
system($cmd);                // exec-use
assert($x);                  // assert-use
mcrypt_encrypt($a,$b,$c,$d); // mcrypt-use
wp_remote_get($url);         // wp-ssrf-audit
current_user_can('x');       // wp-authorisation-checks-audit
check_ajax_referer('n');     // wp-csrf-audit
require $path;                // wp-file-inclusion-audit
$wpdb->query($sql);          // wp-sql-injection-audit
$safe = "constant";          // ok: nothing
