<?php
// taint assigned in loop body, used after (back-edge φ carries it out)
while ($c) { $y = $_GET['x']; }
system($y);                         // 4: BUG

// taint into loop body
$z = $_GET['y'];
while ($d) { system($z); }          // 7: BUG

// do-while: taint in body
do { $w = $_GET['z']; } while ($e);
system($w);                         // 10: BUG

// no taint through loop
while ($f) { $q = "safe"; }
system($q);                         // 13: safe
