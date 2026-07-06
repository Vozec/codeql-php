<?php
// COMPLEX flows batch 6 — more syntaxes. Source $_GET, sink system()/DB.

// 1. __toString magic when object used as string
class S1 { public $v; public function __toString() { return $this->v; } }
$s1 = new S1(); $s1->v = $_GET['a']; system("x" . $s1);        // WANT tostring

// 2. __invoke — object called like a function
class Inv2 { public function __invoke($x) { return $x; } }
$i2 = new Inv2(); system($i2($_GET['a']));                     // WANT invoke

// 3. ArrayAccess offsetGet
class AA3 implements ArrayAccess {
  public $d = [];
  public function offsetExists($o): bool { return true; }
  public function offsetGet($o): mixed { return $this->d[$o]; }
  public function offsetSet($o, $v): void { $this->d[$o] = $v; }
  public function offsetUnset($o): void {}
}
$aa3 = new AA3(); $aa3['k'] = $_GET['a']; system($aa3['k']);   // WANT arrayaccess

// 4. generator with `yield from`
function g4() { yield from [$_GET['a']]; }
foreach (g4() as $x4) { system($x4); }                        // WANT yield-from

// 5. reference return then assign
class R5 { public $v = ''; public function &ref() { return $this->v; } }
$r5 = new R5(); $ref = &$r5->ref(); $ref = $_GET['a']; system($r5->v);  // known-gap ref-return (return-by-reference aliasing across method boundary)

// 6. nested list destructuring
[[$a6]] = [[$_GET['a']]]; system($a6);                        // WANT nested-list

// 7. complex string interpolation ${} and {$obj->prop}
class O7 { public $p; } $o7 = new O7(); $o7->p = $_GET['a'];
system("val {$o7->p} end");                                   // WANT complex-interp

// 8. closure `use` by-value capture
$c8 = $_GET['a']; $fn8 = function () use ($c8) { return $c8; }; system($fn8());  // WANT closure-use

// 9. array unpacking with spread in array literal
$arr9 = ['a' => $_GET['a']]; $merged9 = [...$arr9]; system($merged9['a']);  // WANT array-spread-literal

// 10. ternary chain into a method arg into DB
class Q10 { public function run($s) { return $s; } }
$q10 = new Q10(); $val10 = isset($_GET['a']) ? $_GET['a'] : 'x';
\DB::statement($q10->run($val10));                            // WANT ternary-method-db
