<?php
// COMPLEX flows batch 3 — advanced transformations & framework patterns. Source $_GET, sink system()/DB.

// 1. magic __get returning a tainted backing store
class Magic1 {
    private $store = [];
    public function __set($k, $v) { $this->store[$k] = $v; }
    public function __get($k) { return $this->store[$k]; }
}
$m1 = new Magic1(); $m1->x = $_GET['a']; system($m1->x);       // WANT magic-get-set

// 2. array_merge of a tainted array
$a2 = array_merge(['safe' => 1], $_GET); system($a2['x']);     // WANT array-merge

// 3. array_column over tainted rows
$rows3 = [['n' => $_GET['a']]]; $cols3 = array_column($rows3, 'n'); system($cols3[0]);  // WANT array-column

// 4. reference in foreach mutating into a tainted value (by-ref write-back aliases the collection)
$arr4 = ['a']; foreach ($arr4 as &$v4) { $v4 = $_GET['a']; } system($arr4[0]);  // WANT foreach-ref

// 5. generator yielding tainted values
function gen5() { yield $_GET['a']; }
foreach (gen5() as $g5) { system($g5); }                       // WANT generator-yield

// 6. tainted method call inside string interpolation
class Svc6 { public function name() { return $_GET['a']; } }
$s6 = new Svc6(); system("user {$s6->name()}");                // WANT interp-methodcall

// 7. null-coalescing assignment from tainted
$n7 = null; $n7 ??= $_GET['a']; system($n7);                   // WANT null-coalesce-assign

// 8. taint through explode then join
$parts8 = explode(',', $_GET['a']); system(implode('-', $parts8));  // WANT explode-implode

// 9. Laravel data_get on nested tainted structure
$d9 = ['user' => ['name' => request('n')]]; system(data_get($d9, 'user.name'));  // WANT data-get

// 10. taint via sprintf into a DB sink
\DB::statement(sprintf("SELECT * FROM u WHERE n = '%s'", $_GET['a']));  // WANT sprintf-sql
