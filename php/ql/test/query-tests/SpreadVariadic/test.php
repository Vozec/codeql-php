<?php
// Argument unpacking into a variadic parameter: the spread array reaches the `...$a` parameter.
function run(...$a) { system($a[0]); }        // variadic sink
run(...[$_GET['x']]);                          // BUG: spread into variadic
run($_GET['y']);                               // BUG: plain arg into variadic

function collect(...$parts) { return implode('', $parts); }
system(collect(...[$_GET['z'], 'x']));          // BUG: spread + return

function safe(...$a) { echo "no sink"; }
safe(...[$_GET['w']]);                          // safe: variadic param never reaches a sink
