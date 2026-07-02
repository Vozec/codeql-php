<?php
$t = $_GET['x'];
system($t);                              // c01 direct function call
$o->run($t);                             // c02 method call
$o?->run($t);                            // c03 nullsafe method call
Cls::run($t);                            // c04 static call
new Proc($t);                            // c05 object creation (constructor)
"system"($t);                            // c06 string-literal callee
$f = 'system'; $f($t);                   // c07 dynamic call via variable
$m = 'run'; $o->$m($t);                  // c08 dynamic method name
$arr = ['system']; $arr[0]($t);          // c09 callee from array element
call_user_func('system', $t);            // c10 call_user_func
call_user_func_array('system', [$t]);    // c11 call_user_func_array
array_map('system', [$t]);               // c12 array_map callback
$fn = system(...); $fn($t);              // c13 first-class callable
(function($a){ system($a); })($t);       // c14 IIFE closure
$inv($t);                                // c15 __invoke object
