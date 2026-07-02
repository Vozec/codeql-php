<?php
// A.3 — `for` loop modelled with a real back-edge (body → update → condition → body), so the loop
// header carries a φ that merges the pre-loop value with the end-of-iteration value.

// canonical: taint assigned in the body, used after the loop
for ($i = 0; $i < 3; $i++) { $y = $_GET['x']; }
system($y);                         // 7: BUG

// LOOP-CARRIED (the real back-edge discriminator): `$c` is USED before it is (re)assigned inside the
// body, so on iterations >= 2 it holds the tainted value written at the end of the previous iteration.
// Only a back-edge φ at the loop header exposes this; a linearised CFG misses it (false negative).
$c = "safe";
for ($i = 0; $i < 3; $i++) { system($c); $c = $_GET['x']; }   // 13: BUG (needs back-edge)

// no taint through the loop
for ($i = 0; $i < 3; $i++) { $q = "safe"; }
system($q);                         // 17: safe
