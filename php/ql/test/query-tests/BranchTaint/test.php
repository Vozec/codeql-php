<?php
// fall-through (if without else): the other session documented THIS as dropped
$y = "safe";
if ($c) { $y = $_GET['x']; }
system($y);                       // 5: BUG — taint crosses the φ join

// if/else: taint in then-branch
if ($d) { $z = $_GET['y']; } else { $z = "safe"; }
system($z);                       // 9: BUG — φ(then-taint, else-safe)

// if/else: neither branch tainted → must NOT flag
if ($e) { $w = "a"; } else { $w = "b"; }
system($w);                       // 13: safe
