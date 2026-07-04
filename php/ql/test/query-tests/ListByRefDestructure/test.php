<?php
// By-reference elements in list/array destructuring bind the variable (SSA write must see through &).

[$a, &$b] = ["safe", $_GET['x']];
system($b);                                  // 5: BUG (by-ref element)

$rows = [["safe", $_GET['y']]];
foreach ($rows as [$c, &$d]) { system($d); } // 8: BUG (foreach + list by-ref)

// plain destructuring still works
[$e, $f] = ["safe", $_GET['z']];
system($f);                                  // 12: BUG

// a fully-constant destructuring stays safe (destructuring is field-insensitive / recall-first:
// `[$g, &$h] = [taint, "safe"]` would also taint $h — an accepted over-approximation).
[$g, &$h] = ["a", "safe"];
system($h);                                  // 17: safe
