<?php
// A constructor that stores arguments into fields acts as a setter: `$o = new C($t); sink($o->f)`.

// positional arg stored into a field
class C1 { public $v; function __construct($a){ $this->v = $a; } }
$c1 = new C1($_GET['x']);
system($c1->v);                     // 7: BUG

// named arg routed to the right constructor parameter (in order)
class C2 { public $v; function __construct($a, $b){ $this->v = $b; } }
$c2 = new C2(a: "safe", b: $_GET['y']);
system($c2->v);                     // 12: BUG

// constructor property promotion: the promoted parameter IS the field
class DTO { public function __construct(public readonly string $cmd){} }
$d = new DTO($_GET['z']);
system($d->cmd);                    // 17: BUG

// --- precision (must NOT flag) ---

// a field assigned a constant is not tainted (field-precise)
class C3 { public $v; public $w; function __construct($a){ $this->v = $a; $this->w = "safe"; } }
$c3 = new C3($_GET['w']);
system($c3->w);                     // 24: safe

// a DIFFERENT instance of the same class is not tainted (per-instance, no shared-node leak)
$t1 = new C1($_GET['q']);
$t2 = new C1("safe");
system($t2->v);                     // 29: safe

// reordered named args map by NAME, not position (stored param `a` gets the safe value)
class C4 { public $f; function __construct($a, $b){ $this->f = $a; } }
$c4 = new C4(b: $_GET['r'], a: "safe");
system($c4->f);                     // 34: safe
