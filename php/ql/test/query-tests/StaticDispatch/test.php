<?php
// Static dispatch resolved by type: Class::/self::/parent:: go to the right class, not any same-named method.
class Danger { public static function run($x) { system($x); } }
class Safe   { public static function run($x) { return strlen($x); } }
Danger::run($_GET['b']);   // BUG: explicit Danger::run
Safe::run($_GET['c']);     // ok: explicit Safe::run has no sink (name dispatch would FP here)
class Child extends Danger {
  public static function go($y) { parent::run($y); }   // parent:: resolves to Danger::run
}
Child::go($_GET['d']);     // BUG: reaches Danger::run through parent::
