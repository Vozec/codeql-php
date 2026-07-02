<?php
// A.2 — an augmented assignment (`$x .= v`, `$x += v`, …) is a read-modify-write: the LHS is BOTH
// read (old value) and written. Taint on the old value must survive into the result.

// old value tainted, appended-to with a constant — result stays tainted
$a = $_GET['x'];
$a .= "-suffix";
system($a);                         // 8: BUG (was FN: LHS of `.=` not read, old taint dropped)

// tainted value appended INTO a previously-safe variable — result becomes tainted
$b = "prefix-";
$b .= $_GET['y'];
system($b);                         // 13: BUG

// neither side tainted — stays safe
$c = "prefix-";
$c .= "-suffix";
system($c);                         // 18: safe
