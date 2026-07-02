<?php
// A.4 — `match` is an expression whose value is the selected arm's RETURN. Taint on any arm's return
// must reach the result (over-approx: any arm may be selected). The subject only selects, so a tainted
// subject does not by itself taint the result (like a ternary condition).

// a tainted arm return taints the match result
$x = match ($k) { 1 => $_GET['a'], default => "safe" };
system($x);                         // 8: BUG

// a tainted arm return in the default arm
$y = match ($k) { 1 => "safe", default => $_GET['b'] };
system($y);                         // 12: BUG

// tainted SUBJECT alone does not taint the result (subject selects, is not the value)
$z = match ($_GET['sel']) { 1 => "a", default => "b" };
system($z);                         // 16: safe

// all-constant arms — safe
$w = match ($k) { 1 => "a", default => "b" };
system($w);                         // 20: safe
