<?php
// `Closure::fromCallable('func')` builds a closure for the named function (like the `func(...)` syntax).
function passv($x) { return $x; }
function sanitizev($x) { return "safe"; }

$f = Closure::fromCallable('passv');
system($f($_GET['a']));                 // 7: BUG

$g = \Closure::fromCallable('passv');   // leading-backslash form
system($g($_GET['b']));                 // 10: BUG

// a closure from a sanitizing function stays safe
$h = Closure::fromCallable('sanitizev');
system($h($_GET['c']));                 // 14: safe
