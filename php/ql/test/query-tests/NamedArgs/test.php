<?php
function run($a, $cmd) { system($cmd); }
run(cmd: $_GET['x'], a: "safe");     // 3: BUG — named arg cmd (order swapped) reaches $cmd
run(cmd: "ls", a: $_GET['y']);       // 4: ok — $cmd is constant, $a (tainted) unused
