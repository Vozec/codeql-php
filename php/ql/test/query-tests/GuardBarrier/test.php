<?php
// B.5 — a KNOWN sanitizer guard (ctype_alnum, is_numeric, …) barriers the validated variable on the
// branch it controls. An UNKNOWN/custom guard does not (recall-first): the path is still shown.

// known guard: ctype_alnum -> the read of $a inside the then-branch is safe
$a = $_GET['x'];
if (ctype_alnum($a)) {
    system($a);                     // 8: safe (guarded by ctype_alnum)
}

// known guard: is_numeric
$n = $_GET['n'];
if (is_numeric($n)) {
    system($n);                     // 14: safe (guarded by is_numeric)
}

// UNKNOWN/custom guard: not a modelled sanitizer -> still reported (path shown through the if)
$b = $_GET['y'];
if (custom_test($b)) {
    system($b);                     // 20: BUG (custom_test is not known to sanitize)
}

// unguarded use of the same variable -> BUG
$c = $_GET['z'];
system($c);                         // 25: BUG (no guard)

// guarded variable used OUTSIDE the guard -> still BUG (only the guarded read is safe)
$d = $_GET['w'];
if (ctype_alnum($d)) { /* ... */ }
system($d);                         // 30: BUG (use is outside the guarded branch)
