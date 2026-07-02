<?php
// A.5 — short-circuit operators must branch (right operand conditionally evaluated). Covered forms:
$r = $a && $b;
$s = $c || $d;
$t = $e ?? $f;
$u = $a and $b;
$v = $c or $d;
$w = ($a > 0) && ($b < 10) || ($c ?? $d);   // nested / chained
