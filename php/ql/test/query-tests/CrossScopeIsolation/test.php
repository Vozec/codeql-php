<?php
// Scope-local taint steps must NOT link same-named variables across unrelated scopes (false positives).

// --- closure by-value capture `use($x)` is scope-local ---
function a1(){ $x = $_GET['a']; }                          // taint in one scope
function b1(){ $x = "safe"; $c = function() use ($x) { system($x); }; $c(); }  // 6: safe
$xok = $_GET['b']; $cok = function() use ($xok) { system($xok); }; $cok();     // 7: BUG (same scope)

// --- variable-variable to concrete is scope-local ---
function a2(){ $n = 'v'; $$n = $_GET['c']; }
function b2(){ $v = "safe"; system($v); }                  // 11: safe
$m = 'w'; $$m = $_GET['d']; system($w);                    // 12: BUG (same scope)

// --- `global $g` requires the scope to declare it ---
function decl(){ global $g; $g = 1; }
function a3(){ $g = $_GET['e']; }                          // LOCAL $g (no global decl)
function b3(){ $g = "safe"; system($g); }                  // 17: safe (local, unrelated)
function gw(){ global $h; $h = $_GET['f']; }
function gr(){ global $h; system($h); }                    // 19: BUG (real global)
gw(); gr();

// --- `$b =& $a` reference alias is scope-local ---
function a4(){ $p = $_GET['g']; $q =& $p; }
function b4(){ system($q); }                               // 24: safe (unrelated $q)
$r = $_GET['h']; $s =& $r; system($s);                     // 25: BUG (same scope)
