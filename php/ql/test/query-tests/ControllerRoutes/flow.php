<?php
// Real-world routing: the route parameter reaches a DB sink through a CONTROLLER action, and the bug is
// several method calls deep — not a closure directly on the router. Exercises the controller
// route-handler mechanism AND the interprocedural engine.

class UserController
{
    // `[UserController::class, 'show']` handler — $id is the {id} route parameter (user input).
    public function show($id)
    {
        $this->render($id);                                      // call 1
    }

    private function render($v)
    {
        $this->lookup($v);                                       // call 2
    }

    private function lookup($w)
    {
        DB::statement("SELECT * FROM users WHERE id = $w");      // WANT SQLi — 3 calls from the route param
    }

    // `'UserController@destroy'` handler — scalar-typed route param (int $id) is still user input.
    public function destroy(int $id)
    {
        DB::statement("DELETE FROM users WHERE id = $id");       // WANT SQLi
    }

    // A dependency-injected param (class type) is NOT a route parameter — must NOT be a source.
    public function safe(Request $req)
    {
        DB::statement("SELECT 1");                               // ok: no route-param source
    }
}

Route::get('/u/{id}', [UserController::class, 'show']);
Route::delete('/u/{id}', 'UserController@destroy');
Route::get('/safe', [UserController::class, 'safe']);
