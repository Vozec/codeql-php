<?php
$s = $_GET['x'];
function id($p){ return $p; } system(id($s));           // f01 interproc return
function w(&$r){ $r = $_GET['y']; } w($z); system($z);  // f02 by-ref param out
$g = function() use ($s){ system($s); }; $g();          // f03 closure capture by value
$cb = fn() => system($s); $cb();                        // f04 arrow fn capture
function gen(){ yield $_GET['g']; } foreach(gen() as $v){ system($v); } // f05 generator yield
global $glob; $glob = $_GET['h']; function u(){ global $glob; system($glob); } u(); // f06 global
foreach([$s] as $vv){ system($vv); }                    // f07 foreach value
