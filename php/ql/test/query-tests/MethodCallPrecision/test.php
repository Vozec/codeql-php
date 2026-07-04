<?php
// A method call must NOT blanket-pass its arguments to its return value — the callee body decides.

// method that IGNORES its arg (a sanitizer) -> result is safe
class Filter { function clean($x){ return preg_replace('/[^a-z]/', '', "safe"); } }
$f = new Filter();
system($f->clean($_GET['a']));       // 7: safe (was a FP)

// method that RETURNS its arg -> tainted via real interprocedural flow
class Echoer { function ret($x){ return $x; } }
$e = new Echoer();
system($e->ret($_GET['b']));         // 12: BUG

// static method returning its arg -> tainted via interproc
class Util { static function pass($x){ return $x; } }
system(Util::pass($_GET['c']));      // 16: BUG

// receiver taint through a method that returns $this-stored value still works elsewhere (setter tests)
