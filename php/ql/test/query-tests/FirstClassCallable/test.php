<?php
// PHP 8.1 first-class callable syntax `f(...)` creates a callable referencing `f`.
function danger($x) { system($x); }
function wrapret($y) { return $y; }

// FCC to a sink function, called with taint
$fn = danger(...);
$fn($_GET['x']);                 // 8: BUG

// FCC returning its arg, result used
$g = wrapret(...);
$r = $g($_GET['y']);
system($r);                      // 13: BUG

// FCC to a function that ignores its arg -> safe
function ignore($z) { return "const"; }
$h = ignore(...);
system($h($_GET['z']));          // 18: safe
