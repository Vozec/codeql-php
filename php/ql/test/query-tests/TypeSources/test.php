<?php
// exprClass sources: typed property, clone, typed parameter, fluent return $this.
class Exec { public function run($x) { system($x); } }
class Safe { public function run($x) { return strlen($x); } }
class Holder { public Exec $e; public Safe $s; }

$h = new Holder();
$h->e->run($_GET['a']);          // BUG: typed property $h->e is Exec
$h->s->run($_GET['b']);          // ok: typed property $h->s is Safe (name dispatch would FP)

$c = clone $h->e;
$c->run($_GET['c']);             // BUG: clone keeps type Exec

function handle(Exec $x) { $x->run($_GET['d']); }   // BUG: typed parameter Exec
function handleSafe(Safe $x) { $x->run($_GET['e']); } // ok: typed parameter Safe
