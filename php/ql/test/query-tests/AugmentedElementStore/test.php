<?php
// Augmented assignment into an element/property (`.=`, `+=`) redefines the container with the new value.

$a = [];
$a['k'] .= $_GET['a'];
system($a['k']);                        // 6: BUG (array element .=)

class Cmd { public $buf = ""; function add($x){ $this->buf .= $x; } function get(){ return $this->buf; } }
$c = new Cmd();
$c->add($_GET['b']);
system($c->get());                      // 11: BUG (property .= through methods)

// constant appended -> safe
$s = [];
$s['k'] .= "safe";
system($s['k']);                        // 16: safe
