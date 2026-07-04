<?php
// Two-level interprocedural object mutation: an array-element field and a nested-object field, both
// mutated inside a callee, are observed by the caller (generic content model, no enumerated pattern).

// array-element field appended in a method
class Bag { public $items = []; function add($v) { $this->items[] = $v; } }
$bag = new Bag();
$bag->add($_GET['a']);
system($bag->items[0]);              // 9: BUG

// array-element field appended in a constructor
class Bag2 { public $items = []; function __construct($v) { $this->items[] = $v; } }
$bag2 = new Bag2($_GET['b']);
system($bag2->items[0]);             // 14: BUG

// nested object field mutated in a method
class Inner { public $f; }
class Outer { public $inner; function __construct() { $this->inner = new Inner(); } function set($v) { $this->inner->f = $v; } }
$outer = new Outer();
$outer->set($_GET['c']);
system($outer->inner->f);            // 21: BUG

// --- precision (must NOT flag) ---
class Bag3 { public $items = []; function add($v) { $this->items[] = "safe"; } }
$b3 = new Bag3(); $b3->add($_GET['d']);
system($b3->items[0]);               // 26: safe
