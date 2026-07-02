<?php
// A.4b — switch: arms fall through unless `break`. Fall-through carries taint to the next arm; a
// `break` isolates the arm. Taint assigned in an arm also reaches code after the switch.

// FALL-THROUGH: case 1 has no `break`, so its taint reaches the `system` in case 2.
function fall($x) {
    switch ($x) {
        case 1:
            $b = $_GET['u'];
        case 2:
            system($b);              // 11: BUG (fall-through from case 1)
    }
}

// ISOLATION: case 1 `break`s, so its taint does NOT reach case 2 (case 2 is only entered on its own
// match, where $a is undefined).
function isolate($x) {
    switch ($x) {
        case 1:
            $a = $_GET['t'];
            break;
        case 2:
            system($a);              // 23: safe (isolated by break)
    }
}

// taint assigned in an arm reaches code AFTER the switch
function after($x) {
    switch ($x) {
        case 1:
            $c = $_GET['v'];
            break;
        default:
            $c = "safe";
    }
    system($c);                      // 36: BUG (case 1 may execute)
}
