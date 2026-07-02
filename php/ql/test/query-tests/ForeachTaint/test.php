<?php
// A.3 — `foreach` loop modelled with a real back-edge (body → binding header → body), so the loop
// header carries a φ, and a tainted iteration value taints the loop variable.

// canonical: taint assigned in the body, used after the loop
foreach ($items as $it) { $y = $_GET['x']; }
system($y);                         // 7: BUG

// tainted collection → the loop variable is tainted inside the body
foreach ($_GET['arr'] as $v) { system($v); } // 10: BUG

// LOOP-CARRIED (the real back-edge discriminator): `$c` is USED before being (re)assigned in the body,
// so from the 2nd element on it holds the previous iteration's tainted value. Needs a back-edge φ.
$c = "safe";
foreach ($items as $it) { system($c); $c = $_GET['x']; }   // 15: BUG (needs back-edge)

// no taint through the loop
foreach ($items as $it) { $q = "safe"; }
system($q);                         // 19: safe
