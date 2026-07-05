<?php
// `clone` copies an object's fields, so field taint on the source must carry to the clone.
class Box {
    public $val;
}

$a = new Box();
$a->val = $_GET['x'];
$b = clone $a;
system($b->val);              // BUG: $b->val is the cloned tainted $a->val

$c = new Box();
$c->val = "constant";
$d = clone $c;
system($d->val);              // safe: cloned constant

$e = new Box();
$e->val = $_GET['y'];
system((clone $e)->val);      // BUG: clone used inline
