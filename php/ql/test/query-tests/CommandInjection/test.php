<?php
$cmd = $_GET['cmd'];
system($cmd);                                  // BUG: command injection
exec("ls " . $_POST['dir']);                   // BUG: concat
passthru($_REQUEST['x']);                       // BUG
system(escapeshellarg($_GET['safe']));          // ok: sanitized
system("ls -la");                               // ok: constant
$clean = escapeshellcmd($_GET['c']); system($clean); // ok: sanitized via var
