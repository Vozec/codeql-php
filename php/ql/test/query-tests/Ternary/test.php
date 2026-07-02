<?php
$x = $_GET['c'] ? "a" : "b";
system($x);                      // 3: ok — only the CONDITION is tainted, branches constant
$y = $cond ? $_GET['a'] : "b";
system($y);                      // 5: BUG — a branch is tainted
$z = $_GET['e'] ?: "default";
system($z);                      // 7: BUG — elvis, condition is the value
