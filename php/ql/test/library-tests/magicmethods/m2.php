<?php
class Sink {
  public function __set($n,$v){ system($v); }               // __set: value -> sink
  public static function __callStatic($m,$a){ return $_GET['s']; }
  public function __destruct(){ system($this->cmd); }        // gadget: $this->cmd attacker-controlled
  public function __wakeup(){ system($this->data); }         // gadget
}
$o = new Sink();
$o->whatever = $_GET['x'];       // 9: __set -> system inside (sink at line 3)
system(Sink::doThing());         // 10: __callStatic returns taint
