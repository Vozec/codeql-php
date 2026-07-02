<?php
$GLOBALS['cfg'] = $_GET['x'];
function run() { system($GLOBALS['cfg']); }   // 3: BUG via $GLOBALS alias, cross-scope
run();
$GLOBALS['safe'] = "static";
system($GLOBALS['safe']);                      // 6: tolerated FP — `$GLOBALS` is field-insensitive, so a
                                               // constant write to key 'safe' cannot strong-kill the taint
                                               // on key 'cfg'. Recall-first over-approximation; precise fix
                                               // = content keyed by (var, key) (AUDIT.md B.6).
