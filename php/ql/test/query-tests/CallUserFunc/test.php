<?php
// call_user_func / call_user_func_array: args reach the callee's parameters, its return reaches the result.

function echoer($a) { return $a; }
function sanitize($a) { return "safe"; }

system(call_user_func('echoer', $_GET['a']));                 // 7: BUG (string callee)
system(call_user_func(function($x){ return $x; }, $_GET['b'])); // 8: BUG (inline closure)
system(call_user_func(fn($x) => $x, $_GET['c']));             // 9: BUG (arrow)
system(call_user_func_array('echoer', [$_GET['d']]));         // 10: BUG (array of args)

// callee ignores its argument -> safe (no blanket pass-through)
system(call_user_func('sanitize', $_GET['e']));               // 13: safe
