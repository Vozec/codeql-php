<?php
// User's exact scenario: input → user-fn → user-fn → substr → sink, plus a long chained pipeline.
function test_func($x) { return strtoupper($x); }
function func_test_2($y) { return $y . "_suffix"; }

$a = $_GET['x'];
$a = test_func($a);
$b = func_test_2($a);
system(substr($b, 2));           // 9: BUG (2 user-fn transforms + substr)

// long pipeline of mixed builtin + user-fn transforms
$v = $_GET['y'];
$v = strtoupper($v);
$v = trim($v);
$v = str_replace("a", "b", $v);
$v = substr($v, 1);
$v = test_func($v);
$v = func_test_2($v);
$v = $v . "z";
system($v);                      // 20: BUG (8 chained transforms)

// sanitized pipeline: a real barrier stops it
$w = $_GET['z'];
$w = htmlspecialchars($w);       // sanitizer
system($w);                      // 26: safe (sanitized)
