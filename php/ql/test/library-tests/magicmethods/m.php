<?php
class Wrap {
  private $v;
  public function __construct($x){ $this->v = $x; }
  public function __toString(){ return $this->v; }        // returns tainted field
  public function __get($n){ return $_GET['leak']; }        // magic getter returns taint
  public function __call($m,$a){ return $_GET['c']; }       // magic call returns taint
}
$o = new Wrap($_GET['x']);
system("prefix" . $o);          // 11: __toString in concat -> taint
$o2 = new Wrap("safe");
system($o2->anything);          // 13: __get returns tainted
$o3 = new Wrap("safe");
system($o3->doStuff());         // 15: __call returns tainted
