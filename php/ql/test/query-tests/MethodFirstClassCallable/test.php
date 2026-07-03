<?php
// PHP 8.1 method first-class callable `$obj->m(...)` creates a callable bound to the method.
class R { function run($x){ system($x); } }
$r = new R();
$fn = $r->run(...);
$fn($_GET['x']);                    // 6: BUG
