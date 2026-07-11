<?php
// Class-qualified sources: `$request->get()` is tainted ONLY when the receiver is a Request,
// so the generic method name does not fire on unrelated classes.
class Request {
    public function get($k) {}
    public function header($k) {}
}
class Repository {
    public function get($k) {}     // same name, unrelated class — NOT a source
}

function handle(Request $req) {
    system($req->get('cmd'));       // BUG: Request::get is request input
    system($req->header('X-Cmd'));  // BUG: Request::header
}

function load(Repository $repo) {
    system($repo->get('id'));       // safe: Repository::get is not a request source
}

// Class-qualified STATIC sources: `Input::post()` (Contao) is tainted; the qualifier must match the
// modeled class, so a same-named static method on an unrelated class is NOT a source.
class NotInput {
    public static function post($k) {}
}

function handleStatic() {
    system(Input::post('cmd'));     // BUG: Input::post is a Contao request source
}

function safeStatic() {
    system(NotInput::post('id'));   // safe: NotInput::post is not modeled
}
