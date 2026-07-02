<?php
$b = &$a;
$a = $_GET['x'];
system($b);                    // 4: BUG via reference alias
try {
  throw new Exception($_GET['y']);
} catch (Exception $e) {
  system($e->getMessage());    // 8: BUG via exception message reflection
}
$d = &$c;
$c = "safe";
system($d);                    // 12: ok, constant
