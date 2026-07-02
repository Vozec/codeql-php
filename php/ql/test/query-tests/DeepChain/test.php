<?php
// 6-level interprocedural chain: source -> h1 -> h2 -> h3 -> h4 -> h5 -> sink
function h5($e) { system($e); }              // sink at the bottom
function h4($d) { h5($d); }
function h3($c) { h4($c); }
function h2($b) { h3($b); }
function h1($a) { h2($a); }
function entry() { h1($_GET['x']); }         // source at the top

// interprocedural via method dispatch + return values, several hops
class A { function wrap($v) { return $v; } }
class B { function forward($w) { $a = new A(); return $a->wrap($w); } }
function chained() {
    $b = new B();
    $r = $b->forward($_GET['y']);            // 2 method hops + return
    system($r);                              // sink
}

// deep nesting of expressions (structural recursion) inside a deep call chain
function nested($p) { return strtoupper(trim("x" . $p . "y")); }
function deepExpr() {
    $t = nested(nested($_GET['z']));         // nested calls + nested string ops
    system($t);
}
