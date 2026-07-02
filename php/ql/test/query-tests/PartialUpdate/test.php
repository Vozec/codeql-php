<?php
// A.1 — a partial update (`$x[k]=v` / `$x->p=v`) is a WEAK write: it must NOT kill a prior tainted
// definition of the whole variable. Recall-first: the old value may still be present.

// element update between taint and use — taint must survive
$a = $_GET['x'];
$a[0] = 'z';
system($a);                         // 8: BUG (was a false negative: element write killed $a)

// property update between taint and use — taint must survive
$o = $_GET['y'];
$o->p = 'z';
system($o);                         // 13: BUG (was a false negative: property write killed $o)

// nested element update between taint and use — taint must survive
$b = $_GET['z'];
$b['k']['j'] = 'z';
system($b);                         // 18: BUG

// no taint ever: a partial update must not conjure taint
$c = "safe";
$c[0] = 'z';
system($c);                         // 23: safe

// the updated element itself is not the source of truth here — we read the whole variable, which
// carries the original taint regardless of the (field-insensitive) partial write.
