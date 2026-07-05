<?php
// A variable method name `$o->$m()` dispatches to the method $m resolves to.
class Handler {
    function run($x) { system($x); }        // sink
    function safe($x) { }                    // no sink
    function echoback($x) { return $x; }
}
$o = new Handler();

$m = 'run';
$o->$m($_GET['a']);                          // BUG: dispatches to run()

$m2 = 'echoback';
system($o->$m2($_GET['b']));                 // BUG: return flows back

$m3 = 'safe';
$o->$m3($_GET['c']);                         // safe: dispatches to safe(), no sink
