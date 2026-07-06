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

// Symfony attribute-routed controller: the #[Route] method's scalar param is a URL placeholder.
class ProductController
{
    #[Route('/product/{slug}')]
    public function view(string $slug, Connection $conn)
    {
        $conn->executeQuery("SELECT * FROM products WHERE slug = '$slug'");  // WANT SQLi (attribute route)
    }
}

// Laravel RESTful resource controller: Route::resource maps to conventional actions by name; show/update
// receive the {photo} id (update's id is the SECOND param, after the injected Request).
class PhotoController
{
    public function show($id)
    {
        DB::statement("SELECT * FROM photos WHERE id = $id");           // WANT SQLi (resource show)
    }

    public function update(Request $request, $id)
    {
        DB::statement("UPDATE photos SET n = 1 WHERE id = $id");        // WANT SQLi (resource update)
    }

    public function index()
    {
        DB::statement("SELECT * FROM photos");                         // ok: no route parameter
    }
}

Route::resource('photos', PhotoController::class);

