<?php
// B.1 — by-reference output parameters carry taint back to the caller's argument variable, for
// FUNCTIONS and METHODS alike.

// function by-ref (already worked)
function fill_fn(&$out) { $out = $_GET['x']; }
fill_fn($a);
system($a);                          // 8: BUG

// method by-ref (was a false negative)
class Filler { function fill(&$out) { $out = $_GET['y']; } }
$f = new Filler();
$f->fill($b);
system($b);                          // 14: BUG

// by-ref that writes a constant -> safe
class Safe { function fill(&$out) { $out = "const"; } }
$s = new Safe();
$s->fill($c);
system($c);                          // 20: safe
