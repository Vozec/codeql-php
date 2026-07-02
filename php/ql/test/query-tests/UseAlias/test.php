<?php
namespace Vendor { class Danger { public function run($x) { system($x); } } }
namespace App {
  use Vendor\Danger as D;
  $x = new D();
  $x->run($_GET['a']);          // 6: BUG — aliased class resolves to Vendor\Danger::run
}
