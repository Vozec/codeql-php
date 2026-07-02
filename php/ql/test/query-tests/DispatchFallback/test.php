<?php
// B.4 — call resolution must fall back to name-based dispatch when the receiver's inferred class has
// no matching method (e.g. the method is provided elsewhere, via a trait/mixin/__call, or the type is
// under-approximated). Gating the fallback on "a type was inferred" (rather than "a typed callee was
// found") silently DROPS the call edge → a false negative. Recall-first: over-approximate instead.

class Runner {
    function run($x) {
        system($x);                 // sink reached through the callee
    }
}

// `Box` has NO `run` method; its instance is used to call `run(...)`. The inferred receiver type is
// `Box`, but no `Box::run` exists, so resolution must fall back by name to `Runner::run`.
class Box {
    public $inner;
}

function f() {
    $o = new Box();
    $o->run($_GET['x']);            // 21: BUG — falls back to Runner::run by name
}

// precise dispatch still works: a real method on the inferred type is used directly
class Direct {
    function go($y) { system($y); }
}
function g() {
    $d = new Direct();
    $d->go($_GET['y']);             // 30: BUG — resolved precisely to Direct::go
}
