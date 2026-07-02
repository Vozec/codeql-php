<?php
$t = $_GET['x'];
$a['k'] = $t;
system($a['k']);
$o = new stdClass();
$o->prop = $t;
system($o->prop);
class Box {
    private $v;
    public function set($x) { $this->v = $x; }
    public function get() { return $this->v; }
}
$b = new Box();
$b->set($_GET['a']);
system($b->get());
