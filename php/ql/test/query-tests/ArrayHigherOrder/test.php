<?php
// Array higher-order functions carry taint from the data array to the result, for any callback kind.

// array_map with a STRING callback (was a false negative)
$a = array_map('strtoupper', $_GET);
system($a[0]);                       // 6: BUG

// array_map with a variable callback
$cb = 'trim';
$b = array_map($cb, $_GET);
system($b[0]);                       // 11: BUG

// array_filter (array is arg 0)
$c = array_filter($_GET, 'is_string');
system($c[0]);                       // 15: BUG

// safe: mapping a constant array
$d = array_map('strtoupper', ["safe", "const"]);
system($d[0]);                       // 19: safe
