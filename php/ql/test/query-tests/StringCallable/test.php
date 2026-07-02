<?php
// B.2 — a string function name stored in a variable and called through it (`$fn(...)`) resolves to the
// named function (dynamic dispatch by name), so taint flows into it.
function danger($x) { system($x); }
function wrapret($y) { return $y; }

// string callable stored, then invoked
$fn = 'danger';
$fn($_GET['a']);                     // 9: BUG ($fn -> danger($x) -> system)

// string callable returning its arg
$g = 'wrapret';
$r = $g($_GET['b']);
system($r);                          // 14: BUG

// safe: string callable to a function that ignores its arg
function ignore($z) { return "const"; }
$h = 'ignore';
system($h($_GET['c']));              // 19: safe
