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
  exists(FunctionCall c |
    c.getName() =
      ["getenv", "apache_request_headers", "getallheaders", "filter_input", "filter_input_array"] and
    n.asExpr() = c
  )
  or
  // Framework request helpers (Laravel `request()`, WordPress, etc.).
  exists(FunctionCall c | c.getName() = ["request", "wp_unslash"] and n.asExpr() = c)
  or
  // Framework request objects: `$request->input()`, `Request::get()`, `Input::all()`, Symfony
  // `$request->query->get()`, `$request->getContent()`, PSR-7 `getQueryParams()`, …
  exists(MethodCall c |
    c.getMethodName() =
      [
        "input", "query", "post", "get", "all", "cookie", "header", "getContent", "json",
        "getQueryParams", "getParsedBody", "getUri", "getRequestUri", "getPathInfo", "fetch",
        "fetchAll", "getClientOriginalName"
      ] and
    n.asExpr() = c
  )
  or
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

/** Functions whose result is a sanitized (safe) value, acting as a taint barrier. */
predicate isSanitizerFunction(string name) {
  name =
    [
      // XSS / output
      "htmlspecialchars", "htmlentities", "strip_tags", "esc_html", "esc_attr", "esc_url",
      "esc_js", "sanitize_text_field", "sanitize_email", "wp_kses", "wp_kses_post",
      // Command
      "escapeshellarg", "escapeshellcmd",
      // SQL
      "mysqli_real_escape_string", "mysql_real_escape_string", "pg_escape_string",
      "pg_escape_literal", "addslashes", "quote",
      // Numeric / type coercion
      "intval", "floatval", "doubleval", "abs", "count", "settype",
      // Path
      "basename", "realpath",
      // Validation/encoding
      "filter_var", "ctype_alnum", "ctype_digit", "preg_quote", "urlencode", "rawurlencode",
      "base64_encode", "bin2hex", "md5", "sha1", "hash"
    ]
}

/** Holds if `n` is the result of a sanitizer call (a taint barrier). */
predicate isSanitizer(DataFlow::Node n) {
  exists(FunctionCall c | isSanitizerFunction(c.getName()) and n.asExpr() = c)
  or
  exists(MethodCall c | c.getMethodName() = ["quote", "escape", "real_escape_string"] and n.asExpr() = c)
  or
  // Numeric casts sanitize.
  exists(CastExpr cast | cast.getTypeName() = ["int", "integer", "float", "double", "bool", "boolean"] and n.asExpr() = cast)
}

/** Maps a dangerous built-in function name to the vulnerability `kind` its arguments expose. */
string sinkFunctionKind(string fname) {
  fname = ["system", "exec", "shell_exec", "passthru", "proc_open", "popen"] and
  result = "command injection"
  or
  fname = ["eval", "assert", "create_function"] and result = "code injection"
  or
  fname = ["mysqli_query", "mysql_query", "pg_query", "pg_send_query"] and result = "SQL injection"
  or
  fname = ["print", "printf", "print_r", "vprintf"] and result = "reflected XSS"
  or
  fname = ["include", "require", "include_once", "require_once"] and result = "file inclusion"
  or
  fname =
    [
      "fopen", "file_get_contents", "file_put_contents", "readfile", "file", "unlink", "fwrite",
      "copy", "rename", "mkdir", "rmdir", "scandir", "opendir"
    ] and
  result = "path traversal"
  or
  fname = ["header", "http_redirect"] and result = "open redirect"
  or
  fname = ["curl_setopt", "curl_init", "fsockopen", "stream_socket_client", "get_headers"] and
  result = "server-side request forgery"
  or
  fname = ["ldap_search", "ldap_list", "ldap_read", "ldap_bind"] and result = "LDAP injection"
  or
  fname = "unserialize" and result = "unsafe deserialization"
}

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
  exists(FunctionCall c | kind = sinkFunctionKind(c.getName()) and n.asExpr() = c.getAnArgument())
  or
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
  exists(MethodCall c |
    c.getMethodName() =
      [
        "query", "exec", "unbuffered_query", "real_query", // PDO / mysqli (NB: `prepare` is SAFE)
        "whereRaw", "orWhereRaw", "havingRaw", "selectRaw", "raw", "statement", // Laravel
        "createQuery", "executeQuery", "executeStatement", "getResult" // Doctrine
      ] and
    n.asExpr() = c.getAnArgument() and
    kind = "SQL injection"
  )
  or
  exists(EchoStmt e | n.asExpr() = e.getAnOperand() and kind = "reflected XSS")
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
