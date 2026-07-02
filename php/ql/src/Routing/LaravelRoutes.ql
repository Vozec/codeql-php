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
import codeql.php.ast.internal.TreeSitter

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
    path = c.getArgument(0).(Php::String).getChild(_).(Php::StringContent).getValue()
    or
    not c.getArgument(0) instanceof Php::String and path = "<dynamic>"
  ) and
  (
    handler = c.getArgument(1).(Php::String).getChild(_).(Php::StringContent).getValue()
    or
    c.getArgument(1) instanceof Php::AnonymousFunction and handler = "<closure>"
    or
    c.getArgument(1) instanceof Php::ArrowFunction and handler = "<closure>"
    or
    exists(Php::ArrayCreationExpression a | a = c.getArgument(1)) and handler = "<[Controller::class, method]>"
    or
    not exists(c.getArgument(1)) and handler = "<none>"
  )
}

from Call c, string verb, string path, string handler
where laravelRoute(c, verb, path, handler)
select c, "Laravel route [" + verb.toUpperCase() + "] " + path + " -> " + handler
