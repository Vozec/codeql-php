<?php
// A.7 — with real branching in place, a re-assignment within the SAME branch is a strong update that
// kills the prior tainted value. The old uncertain-writes hack (every conditional write marked as a
// may-write) kept the tainted value alive → a false positive. These cases pin the correct behaviour.

// sanitize within the branch: the second write kills the taint -> SAFE (was a FP under the hack)
function sanitize_same_branch($c) {
    if ($c) {
        $y = $_GET['x'];
        $y = "safe";
        system($y);                 // 11: safe
    }
}

// taint assigned only in one branch still flows out through the join φ -> BUG
function cross_branch($c) {
    $z = "safe";
    if ($c) {
        $z = $_GET['y'];
    }
    system($z);                     // 21: BUG
}

// tainted in one branch, safe in the other: the tainted branch is still reported -> BUG
function either_branch($c) {
    if ($c) {
        $w = $_GET['z'];
    } else {
        $w = "safe";
    }
    system($w);                     // 31: BUG
}

// re-sanitized after the branch -> SAFE
function sanitize_after($c) {
    $v = "safe";
    if ($c) { $v = $_GET['q']; }
    $v = "clean";
    system($v);                     // 39: safe
}
