<?php
$GLOBALS['cfg'] = $_GET['x'];
function run() { system($GLOBALS['cfg']); }   // 3: BUG via $GLOBALS alias, cross-scope
run();
$GLOBALS['safe'] = "static";
system($GLOBALS['safe']);                      // 6: ok, constant
