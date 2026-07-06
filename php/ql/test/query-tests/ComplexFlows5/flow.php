<?php
// COMPLEX flows batch 5 — very common real-world patterns. Source $_GET, sink system()/DB.

// 1. extract() imports the superglobal into local variables (classic dangerous pattern)
extract($_GET); system($id ?? '');                             // known-gap extract (dynamic var creation)

// 2. compact() then read back
$name = $_GET['a']; $c2 = compact('name'); system($c2['name']);  // known-gap compact (dynamic var read)

// 3. variable-variable
$k3 = 'v'; $$k3 = $_GET['a']; system($v);                       // WANT variable-variable

// 4. taint through a trait method
trait T4 { public function pass($x) { return $x; } }
class C4 { use T4; }
$o4 = new C4(); system($o4->pass($_GET['a']));                  // WANT trait-method

// 5. interface-typed dispatch (impl resolved by subtype)
interface I5 { public function run($x); }
class Impl5 implements I5 { public function run($x) { return $x; } }
function useI5(I5 $svc) { system($svc->run($_GET['a'])); }      // WANT interface-dispatch
useI5(new Impl5());

// 6. array_walk with by-ref callback mutating elements
$a6 = ['x']; array_walk($a6, function (&$v) { $v = $_GET['a']; }); system($a6[0]);  // known-gap array-walk-byref

// 7. preg_replace_callback where the callback returns tainted
$r7 = preg_replace_callback('/x/', function ($m) { return $_GET['a']; }, 'xx'); system($r7);  // WANT preg-replace-callback

// 8. enum backed value from input
enum E8: string { case A = 'a'; }
$e8 = E8::tryFrom($_GET['a']); system($e8->value);             // ok: enum value is bounded to enum constants (allowlist)

// 9. list destructuring with a skipped element
[, $b9] = ['skip', $_GET['a']]; system($b9);                   // WANT list-skip

// 10. deeply chained: request -> array -> object property -> method -> concat -> DB
class Wrap10 { public $d; public function get() { return $this->d; } }
$w10 = new Wrap10(); $w10->d = request('x');
\DB::statement("SELECT " . $w10->get());                       // WANT deep-chain-db
