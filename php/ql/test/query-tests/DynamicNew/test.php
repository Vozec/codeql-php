<?php
class Danger { public function run($x) { system($x); } }
class Safe { public function run($x) { return strlen($x); } }
$c = 'Danger';
$o = new $c();
$o->run($_GET['x']);          // 6: BUG — dynamic new $c resolves to Danger
$c2 = 'Safe';
$o2 = new $c2();
$o2->run($_GET['y']);         // 9: ok — resolves to Safe (no sink)
