/**
 * Cross-CMS ACCESS-CONTROL modelling — a layer ON TOP of the taint pack (new file, no core change).
 *
 * The taint queries answer "does attacker data reach a dangerous INJECTION sink?". Broken-access-control /
 * missing-authorization / IDOR / privilege-escalation are a different shape: a **sensitive operation
 * reachable from an attacker-reachable entrypoint WITHOUT an authorization guard on the path**. There is no
 * injection sink — the operation (delete a post, write an option, change a role) is legitimate *if you are
 * allowed*. The bug is the ABSENCE of a capability check.
 *
 * This library models three data-driven, framework-agnostic concepts (populated by `ext/access-control.model.yml`):
 *   - `entrypointModel`        — attacker-reachable handlers + their privilege level (unauth / authenticated).
 *   - `authorizationGuardModel`— calls that PROVE authorization (WP `current_user_can`, Symfony
 *                                `denyAccessUnlessGranted`, Laravel `authorize`, PrestaShop token checks, …).
 *                                Deliberately NOT: nonce / `is_admin` / `is_user_logged_in` — those are
 *                                authenticity/authentication, not authorization (the dominant WP bounty bug).
 *   - `sensitiveActionModel`   — state-changing / sensitive operations (delete/update/insert/option-write/
 *                                file-delete/role-mutation), tagged with a category.
 *
 * A finding = an entrypoint handler that performs a sensitive action but contains no authorization guard.
 * v1 scope: the guard/action are sought within the handler callable body (the idiomatic WP/PrestaShop
 * pattern where the capability check lives in the handler). Guard-in-callee is a documented limitation.
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.dataflow.internal.TypeInference as TI
import codeql.php.security.ModelExtensions

/** A call that PROVES the current user is authorized for the action (framework-specific, data-driven). */
extensible predicate authorizationGuardModel(string subjectKind, string name);

/**
 * A sensitive / state-changing operation. `category`:
 *   "state-change"   — create/update/delete of a resource, option, setting, file.
 *   "privilege"      — role/capability mutation (privilege escalation if attacker-influenced).
 *   "sensitive-read" — reads data that is then returned/exposed (IDOR disclosure).
 * `argIndex` (-1 = any) marks the argument that is the resource selector, used by the IDOR variant.
 */
extensible predicate sensitiveActionModel(string subjectKind, string name, int argIndex, string category);

/**
 * An attacker-reachable entrypoint router. `handlerArg` = the argument holding the handler callable.
 * `argPrefix` (or "") — when non-empty, the router only counts when a STRING argument (arg `prefixArg`)
 * starts with this prefix (WP: `add_action('wp_ajax_nopriv_…', cb)`). `privLevel` ∈ {unauthenticated,
 * authenticated}.
 */
extensible predicate entrypointModel(
  string subjectKind, string name, int handlerArg, int prefixArg, string argPrefix, string privLevel
);

/** The literal string value of a node (plain or encapsed), for matching action-name prefixes. */
private string stringVal(AstNode e) {
  result = e.(StringLiteral).getValue()
  or
  result = e.(Php::EncapsedString).getChild(0).(Php::StringContent).getValue()
}

/** Resolve a handler-argument expression to the callable it dispatches to: a closure, a resolved array
 *  callable `[Class::class,'m']` / `[$o,'m']`, or a string function-name `'my_handler'`. */
private Callable resolveHandler(AstNode arg) {
  (arg instanceof Php::AnonymousFunction or arg instanceof Php::ArrowFunction) and result = arg
  or
  result = TI::arrayCallableMethod(arg)
  or
  // `[Class::class, 'm']`
  exists(Php::ArrayCreationExpression a, ClassLike c, string m |
    a = arg and
    c.getName() =
      a.getChild(0)
          .(Php::ArrayElementInitializer)
          .getChild(0)
          .(Php::ClassConstantAccessExpression)
          .getChild(0)
          .(Php::Name)
          .getValue() and
    m = a.getChild(1).(Php::ArrayElementInitializer).getChild(0).(StringLiteral).getValue() and
    result = c.getAMethod() and
    result.(Method).getName() = m
  )
  or
  // plain string function name `'my_ajax_handler'`
  exists(string s | s = arg.(StringLiteral).getValue() and result.(Function).getName() = s)
}

/**
 * A convention-named method entrypoint: some CMS dispatch by method name, not a router call (PrestaShop
 * `ajaxProcess<X>()` / `process<X>()`, etc.). `namePattern` is a `matches`-style glob; `privLevel` the
 * reachability. This complements the router-based `entrypointModel` for non-router frameworks.
 */
extensible predicate methodEntrypointModel(string namePattern, string privLevel);

/** Holds if callable `c` is dispatched by an entrypoint router matching `privLevel`. A callable can match
 *  several rows (e.g. a `wp_ajax_nopriv_x` string starts with both `wp_ajax_nopriv_` and `wp_ajax_`). */
private predicate entrypointMatch(Callable c, string privLevel) {
  exists(Call route, string sk, string nm, int hi, int pi, string prefix |
    entrypointModel(sk, nm, hi, pi, prefix, privLevel) and
    (
      sk = "function" and route.(FunctionCall).getName() = nm
      or
      sk = "staticmethod" and route.(StaticMethodCall).getMethodName() = nm
      or
      sk = "method" and route.(MethodCall).getMethodName() = nm
    ) and
    c = resolveHandler(route.getArgument(hi)) and
    (prefix = "" or stringVal(route.getArgument(pi)).matches(prefix + "%"))
  )
  or
  exists(string pat | methodEntrypointModel(pat, privLevel) | c.(Method).getName().matches(pat))
}

/** An attacker-reachable entrypoint handler callable. */
class Entrypoint extends Callable {
  Entrypoint() { entrypointMatch(this, _) }

  /** The MOST severe privilege level the entrypoint is reachable at (unauthenticated > authenticated), so a
   *  `wp_ajax_nopriv_*` handler is reported as unauthenticated, not double-counted. */
  string getPrivilegeLevel() {
    if entrypointMatch(this, "unauthenticated")
    then result = "unauthenticated"
    else result = "authenticated"
  }
}

/** The body node of a callable (closure/arrow/function/method). */
private AstNode callableBody(Callable c) {
  result = c.(Php::AnonymousFunction).getBody() or
  result = c.(Php::ArrowFunction).getBody() or
  result = c.(Php::FunctionDefinition).getBody() or
  result = c.(Php::MethodDeclaration).getBody()
}

/** A call inside callable `c`'s body (transitively). */
private Call callIn(Callable c) { result.(Php::AstNode).getParent+() = callableBody(c) }

/** A global function directly called from `c`'s body, resolved by name (function names are global in PHP,
 *  so this is precise). Method-call resolution is intentionally omitted here (needs receiver types). */
private Function directCallee(Callable c) {
  exists(FunctionCall fc | fc = callIn(c) and fc.getName() = result.getName())
}

/** The set of callables reachable from `c` by following global function calls (bounded by the finite set
 *  of functions). Lets an entrypoint that DELEGATES the sensitive work to a helper still be analysed. */
private Callable reaches(Callable c) {
  result = c
  or
  result = directCallee(reaches(c))
}

/** Holds if `call` matches `authorizationGuardModel`. */
predicate isAuthorizationGuard(Call call) {
  exists(string sk, string nm | authorizationGuardModel(sk, nm) |
    sk = "function" and call.(FunctionCall).getName() = nm
    or
    sk = "method" and call.(MethodCall).getMethodName() = nm
    or
    sk = "staticmethod" and call.(StaticMethodCall).getMethodName() = nm
  )
}

/** Holds if `call` matches `sensitiveActionModel`, binding its `category`. */
predicate isSensitiveAction(Call call, string category) {
  exists(string sk, string nm | sensitiveActionModel(sk, nm, _, category) |
    sk = "function" and call.(FunctionCall).getName() = nm
    or
    sk = "method" and call.(MethodCall).getMethodName() = nm
    or
    sk = "staticmethod" and call.(StaticMethodCall).getMethodName() = nm
  )
}

/** Holds if the entrypoint `e`, or any helper it reaches, contains an authorization guard. Inter-procedural
 *  so a capability check factored into a shared helper still suppresses the finding (fewer false positives). */
predicate hasGuard(Entrypoint e) { isAuthorizationGuard(callIn(reaches(e))) }

/**
 * A MISSING-AUTHORIZATION finding: an attacker-reachable entrypoint that performs a sensitive action —
 * directly OR via a helper it reaches — with NO authorization guard anywhere on that reachable code. `action`
 * is the offending call; `category` its kind; `priv` the entrypoint's privilege level (unauthenticated is
 * the most severe).
 */
predicate missingAuthorization(Entrypoint e, Call action, string category, string priv) {
  action = callIn(reaches(e)) and
  isSensitiveAction(action, category) and
  priv = e.getPrivilegeLevel() and
  not hasGuard(e)
}

// ---- IDOR support (used by Idor.ql, a taint query) ------------------------------------------------

/** The RESOURCE-SELECTOR argument index of a sensitive action call — the `argIndex` of a
 *  `sensitiveActionModel` row with a concrete index (>= 0). A request value flowing here selects which
 *  object is acted on; if the context is unguarded that is IDOR / broken access control. */
predicate sensitiveResourceArg(Call call, int argIndex, string category) {
  exists(string sk, string nm |
    sensitiveActionModel(sk, nm, argIndex, category) and argIndex >= 0
  |
    sk = "function" and call.(FunctionCall).getName() = nm
    or
    sk = "method" and call.(MethodCall).getMethodName() = nm
    or
    sk = "staticmethod" and call.(StaticMethodCall).getMethodName() = nm
  )
}

/**
 * Holds if `call` is NOT authorization-gated: no authorization guard appears in the sink's own enclosing
 * callable(s) (the function/method lexically containing it). A real capability gate is almost always in the
 * same function as the sensitive call (`if (!current_user_can(..)) return; ...; wp_delete_post(..)`).
 * TRANSITIVE callee/caller reachability was tried and rejected: over global function names it connects an
 * interconnected plugin's handler to unrelated guarded functions and silently suppresses real bugs.
 * Guard-in-a-directly-called-wrapper is a documented residual limitation.
 */
predicate isUnguardedContext(Call call) {
  exists(Callable c | call = callIn(c)) and
  not exists(Callable c | call = callIn(c) and isAuthorizationGuard(callIn(c)))
}
