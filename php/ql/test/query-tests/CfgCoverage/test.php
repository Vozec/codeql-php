<?php
function demo($x, $arr, $c, $d) {
  $r = $a && $b || $c ?? $d;
  $t = $c ? $a : $b;
  $u = $c ?: $b;
  if ($c) { a(); } elseif ($d) { b(); } else { c(); }
  while ($c) { if ($d) break; continue; }
  do { work(); } while ($c);
  for ($i=0; $i<3; $i++) { if ($d) continue; break; }
  foreach ($arr as $k => $v) { use2($v); }
  switch ($x) { case 1: aa(); break; case 2: case 3: bb(); default: cc(); }
  $m = match($x) { 1,2 => e(), default => f() };
  try { risky(); throw new Exception(); } catch (E $e) { handle($e); } finally { done(); }
  return $r;
  dead();
}
