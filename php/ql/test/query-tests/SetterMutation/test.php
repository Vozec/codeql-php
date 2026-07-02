<?php
// Object mutation flows back to the caller through a setter (lightweight PostUpdate).
class Box { public $v; public function set($x) { $this->v = $x; } }
$b = new Box();
$b->set($_GET['x']);
system($b->v);            // BUG: the setter's mutation flowed back to $b->v
$c = new Box();
$c->set("safe");
system($c->v);            // ok: set with a constant
