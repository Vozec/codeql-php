<?php
// Type-based dispatch: two classes share a method name; only the real target is analysed.
class Dangerous { public function run($x) { system($x); } }        // sink
class Safe      { public function run($x) { return strlen($x); } } // no sink
$a = new Dangerous();
$a->run($_GET['p']);          // BUG: $a is Dangerous -> system
$b = new Safe();
$b->run($_GET['q']);          // ok: $b is Safe -> no sink (name-based dispatch would FP here)

// Inheritance: subclass inherits the dangerous method.
class Child extends Dangerous {}
$c = new Child();
$c->run($_GET['r']);          // BUG: Child inherits Dangerous::run
