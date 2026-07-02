<?php
// B.2 — closures/arrow-fns stored in a variable and called through it (`$cb(...)`) must carry taint
// into the closure's parameters and out through its return (general lambda flow, not a hardcoded list).

// closure stored, then invoked
$cb = function($x) { system($x); };
$cb($_GET['a']);                     // 7: BUG (arg -> closure param -> system)

// closure returns its (tainted) arg, result used
$t = function($y) { return $y; };
$r = $t($_GET['b']);
system($r);                          // 12: BUG

// arrow function
$af = fn($z) => system($z);
$af($_GET['c']);                     // 16: BUG

// safe: closure ignores its argument
$safe = function($u) { return "const"; };
system($safe($_GET['d']));           // 20: safe
