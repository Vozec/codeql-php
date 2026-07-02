<?php
// A.6 — break/continue in loops. Taint-observable cases (the CFG structure is checked by
// CfgAbnormal). break exits the loop; continue re-enters the header; both are consumed by the loop,
// while return/throw propagate out.

// taint assigned before a conditional break still reaches after the loop (break exits normally)
while ($c) {
  $y = $_GET['x'];
  if ($d) { break; }
}
system($y);                         // 11: BUG

// taint carried across a `continue`: assigned at the end, used at the top on the next iteration
$a = "safe";
while ($c) {
  system($a);                       // 16: BUG (loop-carried; may hold prev iteration's taint)
  if ($d) { continue; }
  $a = $_GET['y'];
}

// continue in a for-loop goes through the update; loop-carried taint still flows
$b = "safe";
for ($i = 0; $i < 3; $i++) {
  system($b);                       // 24: BUG (loop-carried)
  if ($d) { continue; }
  $b = $_GET['z'];
}

// no taint anywhere in a loop with break/continue
while ($c) {
  $q = "safe";
  if ($d) { break; }
  if ($e) { continue; }
}
system($q);                         // 35: safe
