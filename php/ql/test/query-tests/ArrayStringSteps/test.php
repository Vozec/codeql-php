<?php
// String splitters and array transforms preserve element taint (Models-as-Data step rows).

$parts = explode(",", $_GET['a']);
system($parts[0]);                   // 5: BUG (explode)

system(array_values(['k' => $_GET['b']])[0]);   // 7: BUG (array_values)

$m = array_merge(["safe"], [$_GET['c']]);
system($m[1]);                       // 10: BUG (array_merge)

$s = array_slice([$_GET['d']], 0, 1);
system($s[0]);                       // 13: BUG (array_slice)

// no taint through these on constant data
$safe = explode(",", "a,b,c");
system($safe[0]);                    // 17: safe
