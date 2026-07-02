<?php
// B.4 — virtual dispatch: a call on an interface/abstract-typed receiver reaches the concrete
// implementation on an implementor/subtype.
interface Handler { function handle($x); }

class ShellHandler implements Handler {
    function handle($x) { system($x); }        // the concrete impl (a sink)
}
class SafeHandler implements Handler {
    function handle($x) { echo "safe"; }
}

// call through an interface-typed parameter -> dispatch to implementors (recall-first)
function dispatch(Handler $h) {
    $h->handle($_GET['x']);                     // 15: BUG (reaches ShellHandler::handle)
}

// abstract base class
abstract class Base { abstract function run($y); }
class RunImpl extends Base { function run($y) { system($y); } }
function go(Base $b) {
    $b->run($_GET['y']);                        // 23: BUG (reaches RunImpl::run)
}
