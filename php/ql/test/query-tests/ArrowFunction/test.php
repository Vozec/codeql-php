<?php
// Arrow functions `fn(...) => expr`: the body expression IS the return value (no `return` statement).

$f = fn($v) => $v;
system($f($_GET['a']));                 // 5: BUG (arg -> body -> result)

$c = $_GET['b'];
$g = fn() => $c;
system($g());                           // 9: BUG (auto-capture)

system((fn($v) => $v)($_GET['c']));     // 11: BUG (IIFE)

$data = array_map(fn($x) => $x, [$_GET['d']]);
system($data[0]);                       // 14: BUG (arrow as array_map callback)

// an arrow that ignores its argument is safe
$h = fn($v) => "safe";
system($h($_GET['e']));                 // 18: safe
