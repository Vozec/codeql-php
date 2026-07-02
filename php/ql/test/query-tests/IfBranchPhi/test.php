<?php
// φ at the join after an `if` WITHOUT `else`: the body's tainting write ⊔ the pre-if safe value.
// `system($y)` must be flagged because on the then-path `$y` is attacker-controlled.
$y = "safe";
if ($c) {
    $y = $_GET['x'];
}
system($y);              // BUG: command injection via the then-branch φ
