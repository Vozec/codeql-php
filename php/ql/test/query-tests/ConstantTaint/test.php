<?php
// A runtime constant created by define() carries the taint of its value to every reference.
define('CMD', $_GET['cmd']);
system(CMD);                      // BUG: CMD holds tainted request data

define('SAFE', 'ls -la');
system(SAFE);                     // safe: constant value is a literal

define('OTHER', $_GET['o']);
define('CLEAN', 'echo hi');
system(CLEAN);                    // safe: CLEAN is not OTHER (key-specific)

function useConst() {
    system(CMD);                  // BUG: constants are global — reachable from any scope
}
