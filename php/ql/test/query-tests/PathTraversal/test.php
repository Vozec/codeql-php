<?php
$f = $_GET['file'];
file_get_contents($f);                  // BUG
readfile("/var/data/" . $_GET['p']);    // BUG
fopen(basename($_GET['f']), "r");       // ok: basename
file_get_contents("/etc/config");       // ok: constant
