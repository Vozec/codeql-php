<?php
// A closure capturing a variable BY REFERENCE writes back to the enclosing scope.

// tainted write inside the closure -> flows out via the by-ref capture
$out = "";
$f = function () use (&$out) { $out = $_GET['x']; };
$f();
system($out);                    // 8: BUG

// by-VALUE capture does NOT write back (the outer var is unchanged) -> safe
$safe = "";
$g = function () use ($safe) { $safe = $_GET['y']; };
$g();
system($safe);                   // 14: safe (by value, no write-back)

// constant write by ref -> safe
$c = "";
$h = function () use (&$c) { $c = "const"; };
$h();
system($c);                      // 20: safe
