<?php
class Evil {
  public $payload;
  public function __wakeup(){ $x = (string)$this->payload; system($x); }   // 4: cast field in wakeup
  public function __destruct(){ $this->run(); }                            // calls custom method
  private function run(){ $c = $this->payload; system((string)$c); }        // 6: NO LONGER detected — unknown-type __toString dropped for precision (see cve-cartography iter 5)
}
class Tainter { public function __toString(){ return $_GET['x']; } }
$t = new Tainter();
system("v" . $t);                 // 10: __toString via concat (SSA-resolved)
function takesObj($o){ system("p".$o); }   // 11: NO LONGER detected — unknown-type __toString dropped for precision
