<?php
// Comprehensive PHP-construct taint coverage, measured against the PRODUCTION (shared) taint engine
// used by every real query. Each numbered block flows $_GET (source) into system() (command-injection
// sink); every `// WANT` sink line must appear in the .expected. A regression here means a construct
// stopped carrying taint. (The standalone v1 `codeql.php.dataflow.TaintTracking` engine — NOT used by
// production queries — omits several of these; this test deliberately exercises the shared engine.)

// 1. direct
system($_GET['a']);                                   // WANT

// 2. assignment
$v2 = $_GET['a']; system($v2);                        // WANT

// 3. concatenation
system("p " . $_GET['a']);                            // WANT

// 4. interpolation
$n4 = $_GET['a']; system("run $n4");                  // WANT

// 5. ternary
$v5 = 1 ? $_GET['a'] : "x"; system($v5);              // WANT

// 6. elvis
$v6 = $_GET['a'] ?: "x"; system($v6);                 // WANT

// 7. null-coalesce
$v7 = $_GET['a'] ?? "x"; system($v7);                 // WANT

// 8. match
$v8 = match (1) { default => $_GET['a'] }; system($v8);  // WANT

// 9. array element
$a9 = [$_GET['a']]; system($a9[0]);                   // WANT

// 10. keyed array write/read
$a10 = []; $a10['k'] = $_GET['a']; system($a10['k']); // WANT

// 11. foreach
foreach ([$_GET['a']] as $x11) { system($x11); }      // WANT

// 12. list destructuring
[$d12] = [$_GET['a']]; system($d12);                  // WANT

// 13. string builtin step
system(strtoupper($_GET['a']));                       // WANT

// 14. sprintf
system(sprintf("%s", $_GET['a']));                    // WANT

// 15. instance property
class C15 { public $p; }
$o15 = new C15(); $o15->p = $_GET['a']; system($o15->p);  // WANT

// 16. $GLOBALS
$GLOBALS['g16'] = $_GET['a']; system($GLOBALS['g16']); // WANT

// 17. closure use-by-value
$c17 = $_GET['a']; $f17 = function () use ($c17) { system($c17); }; $f17();  // WANT

// 18. arrow auto-capture
$c18 = $_GET['a']; $g18 = fn() => system($c18); $g18();  // WANT

// 19. function return
function f19($x) { return $x; }
system(f19($_GET['a']));                              // WANT

// 20. method return
class C20 { function m($x) { return $x; } }
$o20 = new C20(); system($o20->m($_GET['a']));        // WANT

// 21. call_user_func — closure callee
system(call_user_func(function($x){ return $x; }, $_GET['a']));  // WANT

// 22. call_user_func — string builtin callee
system(call_user_func('strtoupper', $_GET['a']));     // WANT

// 23. variadic parameter
function f23(...$args) { system($args[0]); }          // WANT (sink here)
f23($_GET['a']);

// 24. argument spread
function f24($x) { system($x); }                      // WANT (sink here)
f24(...[$_GET['a']]);

// 25. recursion
function f25($x, $n) { if ($n <= 0) return $x; return f25($x, $n - 1); }
system(f25($_GET['a'], 3));                           // WANT
