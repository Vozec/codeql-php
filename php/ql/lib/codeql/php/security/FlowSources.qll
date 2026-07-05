/** Shared taint sources and sinks for PHP security queries, on the interprocedural engine. */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.DataFlow
private import codeql.php.dataflow.internal.SsaImpl as SsaImpl
import codeql.php.Concepts
import codeql.php.security.ModelExtensions

/** Holds if `n` is attacker-controlled input (request superglobals and common input helpers). */
predicate isRemoteSource(DataFlow::Node n) {
  n.asExpr().(VariableAccess).getName() =
    ["_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES", "_ENV", "HTTP_RAW_POST_DATA"]
  or
  // NOTE: built-in request/env source functions (getenv, filter_input, apache_request_headers, …) are
  // DATA — `sourceModel` rows in `ext/php-builtins.model.yml`, applied by `DataRemoteSource` (Phase C).
  // NOTE: framework request helpers (`request()`, `wp_unslash`) and request-object accessor METHODS
  // (`input`/`query`/`getContent`/`getQueryParams`/…) are DATA — `sourceModel` rows in the framework
  // `ext/*.model.yml` (Phase C), applied by `DataRemoteSource`.
  // Static request facades keep a TARGET-CLASS restriction (`Request::get`, `Input::all`) that the
  // by-name MAD lookup cannot express, so they stay structural here:
  exists(StaticMethodCall c |
    c.getTargetName() = ["Request", "Input"] and
    c.getMethodName() = ["input", "get", "all", "post", "query", "cookie"] and
    n.asExpr() = c
  )
  or
  // Deserialization gadget (POP chain): when `unserialize()` runs on attacker data, the object's
  // class and field values are attacker-controlled, so `$this->field` inside the magic lifecycle
  // methods (`__wakeup`/`__destruct`/`__unserialize`/`__toString`) is a remote source.
  exists(Php::MemberAccessExpression ma, Method m |
    m.getName() = ["__wakeup", "__destruct", "__unserialize"] and
    ma.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody() and
    ma.getObject().(VariableAccess).getName() = "this" and
    n.asExpr() = ma
  )
}

// NOTE: built-in value-sanitizer functions (htmlspecialchars, escapeshellarg, filter_var, …) are DATA
// — `sanitizerModel` rows in `ext/php-builtins.model.yml`, applied by `DataSanitizer` (Phase C). The
// `ctype_*`/`is_numeric` validators are branch GUARDS, not value-sanitizers (`isSanitizerGuardFunction`).

/**
 * Validator functions used as branch GUARDS: `if (g($x)) { … }` establishes that `$x` is safe on the
 * branch the guard controls (its result is a boolean, not a sanitized value). The NAMES are data (to be
 * migrated to MAD in Phase C); the barrier STRUCTURE (`isGuardedRead`) is general.
 */
predicate isSanitizerGuardFunction(string name) {
  name =
    [
      "ctype_alnum", "ctype_digit", "ctype_alpha", "ctype_xdigit", "ctype_upper", "ctype_lower",
      "is_numeric", "is_int", "is_integer", "is_float", "is_double", "in_array", "array_key_exists",
      "preg_match"
    ]
}

/**
 * Holds if `n` is a read of a variable validated by a sanitizer guard on the branch it controls, e.g.
 * `if (ctype_alnum($x)) { … $x … }`. v1 scope: the positive (then) branch of an `if` whose condition is
 * (or contains) the guard call; dominance-based guards (early-return `if(!g($x))return;`, the `else`
 * branch, `&&` chains) are a future refinement. A CUSTOM/unknown guard is NOT matched, so its path is
 * still reported (recall-first) — modelling it is a one-row data addition, no engine change.
 */
predicate isGuardedRead(DataFlow::Node n) {
  exists(Php::IfStatement ifs, FunctionCall g, Expr checked, Expr use |
    g.(Php::AstNode).getParent*() = ifs.getCondition() and
    isSanitizerGuardFunction(g.getName()) and
    checked = g.getAnArgument() and
    use.(Php::AstNode).getParent*() = ifs.getBody() and
    sameAccessPath(checked, use) and
    use != checked and
    n.asExpr() = use
  )
}

/**
 * Holds if `a` and `b` denote the same access path — the same simple variable (`$x`/`$x`), or the same
 * array element with a constant key (`$arr[0]`/`$arr[0]`, `$arr['k']`/`$arr['k']`). Lets a guard on an
 * array element (`if (is_numeric($octet[0])) …`) sanitize that element's reads, not just plain variables.
 */
private predicate sameAccessPath(Expr a, Expr b) {
  a.(VariableAccess).getName() = b.(VariableAccess).getName()
  or
  // `$var[k]` with a constant key (one level, non-recursive — covers `$octet[0]`, keeps the join cheap).
  exists(Php::SubscriptExpression sa, Php::SubscriptExpression sb |
    sa = a and
    sb = b and
    sa.getChild(0).(VariableAccess).getName() = sb.getChild(0).(VariableAccess).getName() and
    subscriptConstKey(sa) = subscriptConstKey(sb)
  )
}

/** Gets the constant integer or string key of a `$arr[k]` subscript (empty if the key is not constant). */
private string subscriptConstKey(Php::SubscriptExpression sub) {
  result = sub.getChild(1).(Php::Integer).getValue()
  or
  result = sub.getChild(1).(Php::String).getChild(_).(Php::StringContent).getValue()
}

/** Holds if `n` is the result of a sanitizer call (a taint barrier) not already covered by MAD. */
predicate isSanitizer(DataFlow::Node n) {
  exists(MethodCall c | c.getMethodName() = ["quote", "escape", "real_escape_string"] and n.asExpr() = c)
  or
  // Numeric casts sanitize.
  exists(CastExpr cast | cast.getTypeName() = ["int", "integer", "float", "double", "bool", "boolean"] and n.asExpr() = cast)
}

/**
 * Maps a dangerous built-in function name to the vulnerability `kind` its arguments expose — read from
 * the `sinkModel` DATA (`ext/php-builtins.model.yml`), NOT a hardcoded QL list (Phase C). Used by the
 * dynamic-dispatch sinks below (`$fn(...)`, `call_user_func('system', …)`), where the callee name is
 * resolved structurally in QL and then looked up here.
 */
string sinkFunctionKind(string fname) { sinkModel("function", fname, -1, result) }

/** Gets the constant string value of a single- or double-quoted string literal `e`. */
private string constantStringValue(Expr e) {
  e.(Php::String).getChild(_).(Php::StringContent).getValue() = result
  or
  e.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue() = result
}

/** Gets the referenced name if `e` is a first-class callable `name(...)` (PHP 8.1). */
private string firstClassCallableName(Expr e) {
  exists(Php::FunctionCallExpression fc |
    fc = e and
    fc.getArguments().getChild(_) instanceof Php::VariadicPlaceholder and
    result = fc.getFunction().(Php::Name).getValue()
  )
}

/**
 * Gets the function name that a dynamic call `$fn(...)` resolves to via SSA, when `$fn` was assigned
 * a string constant (`$fn = 'system'`) or a first-class callable (`$fn = system(...)`).
 */
private string resolvedDynamicCallName(FunctionCall c) {
  exists(
    VariableAccess fnvar, VariableAccess w, AssignExpr a, SsaImpl::LocalVariable v,
    SsaImpl::Definition def, SsaImpl::Cfg::BasicBlock bbw, int iw, SsaImpl::Cfg::BasicBlock bbr,
    int ir
  |
    c.(Php::FunctionCallExpression).getFunction() = fnvar and
    SsaImpl::variableAccessAt(bbr, ir, fnvar) and
    SsaImpl::Impl::ssaDefReachesRead(v, def, bbr, ir) and
    def.definesAt(v, bbw, iw) and
    SsaImpl::variableAccessAt(bbw, iw, w) and
    a.getLhs() = w
  |
    result = constantStringValue(a.getRhs())
    or
    result = firstClassCallableName(a.getRhs())
  )
}

/** Gets the function name when the callee is written as a string literal, e.g. `"system"($x)`. */
private string stringLiteralCallee(FunctionCall c) {
  exists(AstNode fn | fn = c.(Php::FunctionCallExpression).getFunction() |
    result = fn.(Php::String).getChild(_).(Php::StringContent).getValue()
    or
    result = fn.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue()
  )
}

/** Holds if `n` is a sink of vulnerability class `kind`. */
predicate isSinkOfKind(DataFlow::Node n, string kind) {
  // NOTE: the direct built-in function sink (`system($x)`, …) is DATA — `sinkModel` rows applied by
  // `DataSink` (Phase C). The cases below are STRUCTURAL/dynamic dispatch, keyed by the DATA-backed
  // `sinkFunctionKind` name→kind lookup.
  // Callee written as a string literal: `"system"($x)`.
  exists(FunctionCall c |
    kind = sinkFunctionKind(stringLiteralCallee(c)) and n.asExpr() = c.getAnArgument()
  )
  or
  // Dynamic call `$fn($x)` where `$fn` resolves (via SSA) to a dangerous function name.
  exists(FunctionCall c |
    kind = sinkFunctionKind(resolvedDynamicCallName(c)) and n.asExpr() = c.getAnArgument()
  )
  or
  // `call_user_func('system', $x)` / `call_user_func_array('system', [$x])`.
  exists(FunctionCall c, int i |
    c.getName() = ["call_user_func", "call_user_func_array"] and
    kind = sinkFunctionKind(constantStringValue(c.getArgument(0))) and
    i >= 1 and
    n.asExpr() = c.getArgument(i)
  )
  or
  // `array_map('system', $arr)` / `array_walk` / `array_filter`: elements flow to the callback.
  exists(FunctionCall c |
    c.getName() = ["array_map", "array_walk", "array_filter"] and
    kind = sinkFunctionKind(constantStringValue(c.getArgument(0))) and
    n.asExpr() = c.getArgument(1)
  )
  or
  // NOTE: raw SQL query METHODS (PDO/mysqli `query`/`exec`, Laravel `whereRaw`, Doctrine
  // `executeQuery`, …) are DATA — `sinkModel` method rows in the framework `ext/*.model.yml`
  // (Phase C), applied by `DataSink`.
  exists(EchoStmt e | n.asExpr() = e.getAnOperand() and kind = "reflected XSS")
  or
  // `print $x` / `print($x)` is a language construct (PrintIntrinsic), not a function call.
  exists(Php::PrintIntrinsic p | n.asExpr() = p.getChild() and kind = "reflected XSS")
  or
  // `include $x` / `require $x` (language construct, not a function call) — file inclusion.
  exists(IncludeExpr inc | n.asExpr() = inc.getPath() and kind = "file inclusion")
  or
  // Dynamic callable injection: if the *callee* itself is attacker-controlled, the attacker can
  // invoke an arbitrary function/method (`$fn($x)`, `$arr[0]()`, `$o->$m()`) — arbitrary code exec.
  exists(Php::FunctionCallExpression c |
    (
      c.getFunction() instanceof Php::VariableName or
      c.getFunction() instanceof Php::SubscriptExpression
    ) and
    n.asExpr() = c.getFunction() and
    kind = "code injection"
  )
  or
  exists(Php::MemberCallExpression c |
    c.getName() instanceof Php::DynamicVariableName or c.getName() instanceof Php::VariableName
  |
    n.asExpr() = c.getName() and kind = "code injection"
  )
}

/** The built-in remote sources become `RemoteFlowSource` instances (extensible via QL/data). */
private class BuiltinRemoteSource extends RemoteFlowSource {
  BuiltinRemoteSource() { isRemoteSource(this) }

  override string getSourceType() { result = "remote flow (request data)" }
}

/** The built-in dangerous sinks become `Sink` instances (extensible via QL/data). */
private class BuiltinSink extends Sink {
  string kind;

  BuiltinSink() { isSinkOfKind(this, kind) }

  override string getKind() { result = kind }
}

/** The built-in sanitizer results become `Sanitizer` instances (extensible via QL/data). */
private class BuiltinSanitizer extends Sanitizer {
  BuiltinSanitizer() { isSanitizer(this) }
}

/** A read of a variable validated by a sanitizer guard on its branch becomes a `Sanitizer` (barrier). */
private class GuardBarrier extends Sanitizer {
  GuardBarrier() { isGuardedRead(this) }
}
