<?php
// A.6b — try/catch/finally + throw. Exception message reflection, taint through try/catch bodies,
// and the finally block.

// exception carrying taint → caught → reflected via getMessage()
function reflect() {
    try {
        throw new Exception($_GET['x']);
    } catch (Exception $e) {
        system($e->getMessage());        // 10: BUG
    }
}

// KNOWN v1 LIMITATION (documented FN, AUDIT.md A.6b): only an explicit `throw` transfers control to a
// catch. A call that MAY throw (`maybeThrows()`) has no exceptional edge to the catch, so the taint
// assigned just before it is not seen at `system($y)`. Modelling "any call may throw" (an exceptional
// successor from every call to the enclosing catch) is deferred.
function through() {
    $y = "safe";
    try {
        $y = $_GET['y'];
        maybeThrows();
    } catch (Exception $e) {
        system($y);                      // 24: not flagged — v1 FN (call-may-throw not modelled)
    }
}

// finally always runs; taint assigned there flows out
function fin() {
    try {
        risky();
    } finally {
        $z = $_GET['z'];
    }
    system($z);                          // 35: BUG
}

// no taint anywhere
function safe() {
    try {
        $q = "safe";
    } catch (Exception $e) {
        $q = "also safe";
    }
    system($q);                          // 45: safe
}
