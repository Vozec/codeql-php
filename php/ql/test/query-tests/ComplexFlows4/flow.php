<?php
// COMPLEX flows batch 4 — more syntaxes & transformation functions. Source $_GET, sink system()/DB.

// 1. heredoc interpolation
$h1 = <<<EOT
value is {$_GET['a']} here
EOT;
system($h1);                                                   // WANT heredoc-interp

// 2. first-class callable syntax then invoke
$fn2 = strtoupper(...); system($fn2($_GET['a']));             // WANT first-class-callable->builtin

// 3. static variable persisting a tainted value across calls
function acc3($x) { static $s; if ($x) { $s = $x; } return $s; }
acc3($_GET['a']); system(acc3(null));                         // WANT static-var-persist

// 4. nullsafe method chain
class Svc4 { public function data() { return $_GET['a']; } }
$o4 = new Svc4(); system($o4?->data());                       // WANT nullsafe-chain

// 5. string transform functions as steps (nl2br / ucwords / str_pad / wordwrap)
system(nl2br(ucwords(str_pad($_GET['a'], 20))));             // WANT string-transforms

// 6. exception message carrying tainted data
function thrower6() { throw new \Exception($_GET['a']); }
try { thrower6(); } catch (\Exception $e6) { system($e6->getMessage()); }  // WANT exception-interproc (throw in called fn, caught in caller)

// 7. named-argument call (reordered)
function named7($a, $b) { system($b); }
named7(b: $_GET['a'], a: 'safe');                            // WANT named-args

// 8. array spread with named/string keys into a call
function sp8($x) { system($x); }
sp8(...['x' => $_GET['a']]);                                 // WANT named-spread

// 9. taint through a match with multiple conditions
$v9 = match ($_GET['t']) { 'a', 'b' => $_GET['a'], default => 'x' }; system($v9);  // WANT match-multi

// 10. chained nullsafe property + method into a DB sink
class Repo10 { public $conn; }
class Conn10 { public function q($s) { return $s; } }
$r10 = new Repo10(); $r10->conn = new Conn10();
\DB::statement($r10->conn?->q($_GET['a']));                  // WANT nullsafe-prop-method

// 11. exception DIRECT (no throw/catch) — isolate the new-Exception + getMessage steps
$ed11 = new \Exception($_GET['a']); system($ed11->getMessage());  // WANT exception-direct (new Exception + getMessage steps)

// 12. interprocedural throw via a METHOD call, caught in the caller
class Svc12 { public function risky() { throw new \Exception($_GET['a']); } }
$s12 = new Svc12();
try { $s12->risky(); } catch (\Exception $e12) { system($e12->getMessage()); }  // WANT method-throw-interproc
