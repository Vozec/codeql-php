/**
 * @name Laravel routes
 * @description Enumerates Laravel route registrations (HTTP verb, path, handler) — useful for
 *              attack-surface mapping and driving further taint analysis from controller actions.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id php/laravel-routes
 * @tags routing framework
 */

import codeql.php.AST

/** HTTP verb methods registered on the `Route` facade or a router instance. */
private predicate routeVerb(string name) {
  name = ["get", "post", "put", "patch", "delete", "options", "any", "match", "resource",
      "apiResource", "redirect", "view", "fallback"]
}

/** Holds if `c` is a Laravel route registration; binds its `verb`, `path` and `handler` text. */
predicate laravelRoute(Call c, string verb, string path, string handler) {
  (
    // `Route::get('/x', handler)` / `$router->get(...)`
    exists(StaticMethodCall s | s = c and s.getTargetName() = ["Route", "Router"] and verb = s.getMethodName())
    or
    exists(MethodCall m | m = c and verb = m.getMethodName() and verb != "match")
  ) and
  routeVerb(verb) and
  (
    path = c.getArgument(0).(StringLiteral).getValue()
    or
    not c.getArgument(0) instanceof StringLiteral and path = "<dynamic>"
  ) and
  (
    handler = c.getArgument(1).(StringLiteral).getValue()
    or
    c.getArgument(1) instanceof Closure and handler = "<closure>"
    or
    c.getArgument(1) instanceof ArrayLiteral and handler = "<[Controller::class, method]>"
    or
    not exists(c.getArgument(1)) and handler = "<none>"
  )
}

from Call c, string verb, string path, string handler
where laravelRoute(c, verb, path, handler)
select c, "Laravel route [" + verb.toUpperCase() + "] " + path + " -> " + handler
