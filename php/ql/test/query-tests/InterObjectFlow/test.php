<?php
// Generic interprocedural object-field mutation, handled by the content model (no enumerated pattern):
// a callee that mutates a parameter object's field is observed by the caller after the call.

class Box { public $data; }

// a plain FUNCTION (not a method/setter) mutating a parameter object's field
function fill(Box $b, $x) { $b->data = $x; }
$box = new Box();
fill($box, $_GET['a']);
system($box->data);                 // 11: BUG (mutation returns to the caller's object)

// a two-object chain through a helper function
class Holder { public $v; function put($x){ $this->v = $x; } function take(){ return $this->v; } }
function pipe(Holder $s, Holder $d) { $d->put($s->take()); }
$a = new Holder(); $a->put($_GET['b']);
$b = new Holder();
pipe($a, $b);
system($b->take());                 // 19: BUG (a -> b via pipe, field content across 3 calls)

// --- precision (must NOT flag) ---

// reading the field BEFORE the mutating call is safe (CFG-ordered post-update)
$early = new Box();
system($early->data);               // 25: safe
fill($early, $_GET['c']);

// a DIFFERENT object is not affected by mutating another
$o1 = new Box(); fill($o1, $_GET['d']);
$o2 = new Box();
system($o2->data);                  // 31: safe
