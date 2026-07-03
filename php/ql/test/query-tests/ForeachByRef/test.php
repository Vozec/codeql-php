<?php
// `foreach (... as &$v)` binds $v by reference; the collection still taints the bound variable.

$a = [$_GET['x']];
foreach ($a as &$v) { system($v); }        // 5: BUG (by-ref value)
unset($v);

$b = [$_GET['y']];
foreach ($b as $k => &$w) { system($w); }   // 9: BUG (key + by-ref value)
unset($w);

// by-value still works (regression guard)
$c = [$_GET['z']];
foreach ($c as $u) { system($u); }          // 14: BUG

// constant collection stays safe
$d = ["safe"];
foreach ($d as &$s) { system($s); }         // 18: safe
