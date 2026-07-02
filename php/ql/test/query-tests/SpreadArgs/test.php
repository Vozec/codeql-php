<?php
// Argument unpacking `f(...$args)` reaches the callee's parameters (functions and methods).
function run($a, $b) { system($b); }
$args = ["safe", $_GET['x']];
run(...$args);                       // 5: BUG (tainted element -> a parameter)

class R { function go($a, $b) { system($b); } }
$r = new R();
$margs = [$_GET['y'], "safe"];
$r->go(...$margs);                   // 10: BUG

// safe: spreading a constant array
$safe = ["one", "two"];
run(...$safe);                       // 14: safe
