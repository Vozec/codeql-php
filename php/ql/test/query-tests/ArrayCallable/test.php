<?php
// PHP array callables `[obj|class, 'method']` invoked via call_user_func, a variable, or array_map.
class Handler {
    public function run($x) { system($x); }              // instance method sink
    public static function srun($x) { system($x); }        // static method sink
    public function echoback($x) { return $x; }            // returns its arg
}

$h = new Handler();

// 1. call_user_func with an instance array callable — arg reaches the method param.
call_user_func([$h, 'run'], $_GET['a']);                   // BUG

// 2. Variable-held array callable, invoked dynamically later.
$cb = [$h, 'run'];
$cb($_GET['b']);                                           // BUG

// 3. Class-name (string) static array callable.
call_user_func(['Handler', 'srun'], $_GET['c']);           // BUG

// 4. Return value of the invoked method flows back to the caller.
system(call_user_func([$h, 'echoback'], $_GET['d']));      // BUG

// 5. Safe: constant argument, no taint.
call_user_func([$h, 'run'], "constant");                   // safe
