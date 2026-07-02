<?php
// B.3 — named arguments (PHP 8) route to the parameter by NAME, for functions AND methods, regardless
// of positional order.

// function (already worked)
function run_fn($safe, $cmd) { system($cmd); }
run_fn(cmd: $_GET['x'], safe: "ok");     // 7: BUG (named `cmd` -> $cmd)

// method (was a false negative)
class Runner { function run($safe, $cmd) { system($cmd); } }
$r = new Runner();
$r->run(cmd: $_GET['y'], safe: "ok");    // 12: BUG

// named arg to the SAFE parameter -> safe
$r->run(safe: $_GET['z'], cmd: "ls");    // 15: safe (taint goes to $safe, not the sink)
