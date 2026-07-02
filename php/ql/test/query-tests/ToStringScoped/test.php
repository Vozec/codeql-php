<?php
// __toString is scoped by the receiver's inferred type: a tainted __toString on one class must not
// leak into the string context of an unrelated typed object.
class Leaky { public function __toString() { return $_GET['x']; } }
class Plain { public $v; public function __toString() { return $this->v; } }
$leak = new Leaky();
$plain = new Plain();
system("a" . $leak);     // BUG: Leaky::__toString is tainted
system("b" . $plain);    // ok: Plain is a different type; Leaky's taint must not leak here
