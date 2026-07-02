<?php
$s = $_GET['x'];
$a = $s; system($a);                     // a01 plain =
$b = "x"; $b .= $s; system($b);          // a02 .= augmented
$c = "x"; $c += 0; system($c . $s);      // a03 += augmented
$d =& $s; system($d);                    // a04 reference =&
[$e, $f2] = [$s, 0]; system($e);         // a05 [] destructure
list($g, $h) = [$s, 0]; system($g);      // a06 list() destructure
[[$i]] = [[$s]]; system($i);             // a07 nested destructure
$arr = []; $arr[] = $s; system($arr[0]); // a08 append []=
$arr2['k'] = $s; system($arr2['k']);     // a09 keyed element =
$o->p = $s; system($o->p);               // a10 property =
Cls::$st = $s; system(Cls::$st);         // a11 static property =
$n = 'v'; $$n = $s; system($v);          // a12 variable variable
$x1 = $x2 = $s; system($x1);             // a13 chained assignment
