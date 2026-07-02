/**
 * Provides a taint-tracking model for PHP security queries.
 *
 * v1 engine: taint reachability built on the local def-use data flow (Phase 4), extended with
 * taint steps (string concatenation, interpolation, array reads, taint-propagating built-ins)
 * and a name-based inter-procedural step (argument -> parameter, return -> call). Sources are the
 * request superglobals; sinks are dangerous language constructs; taint stops at values that are
 * not propagated (e.g. the result of `htmlspecialchars`, `escapeshellarg`, numeric casts).
 *
 * The full field-sensitive `shared/dataflow` global engine (with path explanations) is the next
 * step; this model already detects real injections end-to-end.
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.dataflow.DataFlow
private import codeql.php.dataflow.internal.SsaImpl as SsaImpl

module TaintTracking {
  /** The PHP request superglobals whose contents are attacker-controlled. */
  private predicate superglobalName(string name) {
    name = ["_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES", "_ENV", "HTTP_RAW_POST_DATA"]
  }

  /** Built-in functions that pass taint from an argument through to their result. */
  private predicate propagatingBuiltin(string name) {
    name =
      [
        "strtoupper", "strtolower", "ucfirst", "ucwords", "trim", "ltrim", "rtrim", "substr",
        "str_replace", "preg_replace", "sprintf", "vsprintf", "implode", "join", "strrev",
        "str_repeat", "nl2br", "wordwrap", "strval", "urldecode", "rawurldecode", "base64_decode",
        "json_decode", "stripslashes", "html_entity_decode"
      ]
  }

  /** Framework/library calls that return attacker-controlled input. */
  private predicate sourceCallName(string name) {
    name =
      [
        "getenv", "apache_request_headers", "getallheaders", "filter_input", "filter_input_array",
        // Laravel / common helpers
        "input", "request", "query", "all", "post", "get", "cookie", "header"
      ]
  }

  /** A source of taint: a request superglobal, or a call returning user input. */
  predicate isSource(DataFlow::Node node) {
    exists(VariableAccess va | va = node.asExpr() | superglobalName(va.getName()))
    or
    exists(FunctionCall c | sourceCallName(c.getName()) and node.asExpr() = c)
    or
    exists(MethodCall c | sourceCallName(c.getMethodName()) and node.asExpr() = c)
  }

  /** Maps a dangerous built-in function name to the vulnerability `kind` its arguments expose. */
  private string sinkFunctionKind(string fname) {
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

  /** Gets the constant value of a plain single-quoted/double-quoted string literal `e`. */
  private string stringConstantValue(Expr e) {
    result = e.(Php::String).getChild(_).(Php::StringContent).getValue()
  }

  /**
   * Gets a constant string value that expression `e` may hold: either a direct string literal, or a
   * variable read whose reaching SSA definition assigns a string constant.
   */
  private string resolvedStringValue(Expr e) {
    result = stringConstantValue(e)
    or
    exists(
      VariableAccess w, AssignExpr a, SsaImpl::LocalVariable v, SsaImpl::Definition def,
      SsaImpl::Cfg::BasicBlock bbw, int iw, SsaImpl::Cfg::BasicBlock bbr, int ir
    |
      SsaImpl::variableAccessAt(bbr, ir, e) and
      SsaImpl::Impl::ssaDefReachesRead(v, def, bbr, ir) and
      def.definesAt(v, bbw, iw) and
      SsaImpl::variableAccessAt(bbw, iw, w) and
      a.getLhs() = w and
      result = stringConstantValue(a.getRhs())
    )
  }

  /** Gets the function name a dynamic call `$fn(...)` resolves to (e.g. `$fn = 'system'; $fn($x)`). */
  private string resolvedDynamicCallName(FunctionCall c) {
    result = resolvedStringValue(c.(Php::FunctionCallExpression).getFunction())
  }

  /** Holds if `node` is a sink of kind `kind` (e.g. a dangerous call argument). */
  predicate isSink(DataFlow::Node node, string kind) {
    // Direct call to a dangerous built-in: any argument is a sink.
    exists(FunctionCall c |
      kind = sinkFunctionKind(c.getName()) and node.asExpr() = c.getAnArgument()
    )
    or
    // Indirect call via `call_user_func('dangerous', $arg, …)`: the forwarded arguments are sinks.
    exists(FunctionCall c, int i |
      c.getName() = ["call_user_func", "call_user_func_array"] and
      kind = sinkFunctionKind(stringConstantValue(c.getArgument(0))) and
      i >= 1 and
      node.asExpr() = c.getArgument(i)
    )
    or
    // Dynamic call `$fn($arg)` where `$fn` resolves to a dangerous function name.
    exists(FunctionCall c |
      kind = sinkFunctionKind(resolvedDynamicCallName(c)) and node.asExpr() = c.getAnArgument()
    )
    or
    // SQL execution via a database object method.
    exists(MethodCall c |
      c.getMethodName() = ["query", "exec", "prepare", "unbuffered_query", "real_query"] and
      node.asExpr() = c.getAnArgument() and
      kind = "SQL injection"
    )
    or
    // Reflected XSS: anything printed by `echo`.
    exists(EchoStmt e | node.asExpr() = e.getAnOperand() and kind = "reflected XSS")
  }

  /** Gets a function whose body encloses `n` (over-approximate: any ancestor function). */
  private Php::FunctionDefinition enclosingFunction(AstNode n) {
    result.getBody() = n.getParent*()
  }

  /** Gets a method whose body encloses `n` (over-approximate: any ancestor method). */
  private Php::MethodDeclaration enclosingMethod(AstNode n) { result.getBody() = n.getParent*() }

  /** Holds if `va` is a write access (LHS of a simple assignment). */
  private predicate isWrite(VariableAccess va) { SsaImpl::isWriteAccess(va) }

  /** Gets a variable bound by a `foreach` target `t` (a bare variable, a `$k => $v` pair, or a list pattern). */
  private VariableAccess bindingVarIn(Php::AstNode t) {
    result = t
    or
    result = bindingVarIn(t.(Php::Pair).getChild(_))
    or
    result = bindingVarIn(t.(Php::ListLiteral).getChild(_))
  }

  /** Gets a `class::$prop` key identifying a static property access. */
  private string staticPropKey(Php::ScopedPropertyAccessExpression sp) {
    result =
      sp.getScope().(Php::Name).getValue() + "::" +
        sp.getName().(Php::VariableName).getChild().getValue()
  }

  /** Holds if `write` is a variable write access whose SSA definition reaches the read `read`. */
  private predicate defUseFromWrite(VariableAccess write, VariableAccess read) {
    exists(
      SsaImpl::LocalVariable v, SsaImpl::Definition def, SsaImpl::Cfg::BasicBlock bbw, int iw,
      SsaImpl::Cfg::BasicBlock bbr, int ir
    |
      SsaImpl::variableAccessAt(bbw, iw, write) and
      SsaImpl::isWriteAccess(write) and
      def.definesAt(v, bbw, iw) and
      SsaImpl::Impl::ssaDefReachesRead(v, def, bbr, ir) and
      SsaImpl::variableAccessAt(bbr, ir, read)
    )
  }

  /** A single taint propagation step. */
  predicate taintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // 1. Local def-use flow.
    DataFlow::localFlowStep(nodeFrom, nodeTo)
    or
    // 1b. Taint arriving at any variable binding (foreach/global/catch/param/…) reaches its uses.
    defUseFromWrite(nodeFrom.asExpr(), nodeTo.asExpr())
    or
    // 1c. `foreach ($collection as $v)`: the collection taints the value/key binding variables.
    exists(Php::ForeachStatement f, int i |
      i >= 1 and nodeFrom.asExpr() = f.getChild(0) and nodeTo.asExpr() = bindingVarIn(f.getChild(i))
    )
    or
    // 1d. List/array destructuring `[$a, $b] = $rhs`: the whole right-hand side taints every
    //     target variable (element-insensitive over-approximation — never misses a flow).
    exists(Php::AssignmentExpression a, Php::ListLiteral l |
      a.getLeft() = l and nodeFrom.asExpr() = a.getRight() and nodeTo.asExpr() = bindingVarIn(l)
    )
    or
    // 1e. Array literal: a tainted element taints the whole array (element-insensitive).
    exists(Php::ArrayCreationExpression arr, Php::ArrayElementInitializer el |
      el = arr.getChild(_) and nodeFrom.asExpr() = el.getChild(_) and nodeTo.asExpr() = arr
    )
    or
    // 2. String concatenation: either operand taints the result.
    exists(ConcatExpr cat |
      nodeFrom.asExpr() = cat.getAnOperand() and nodeTo.asExpr() = cat
    )
    or
    // 3. String interpolation: an interpolated part taints the string.
    exists(Php::EncapsedString s |
      nodeFrom.asExpr() = s.getChild(_) and nodeTo.asExpr() = s
    )
    or
    // 3b. Heredoc interpolation: an interpolated part taints the heredoc string.
    exists(Php::Heredoc h |
      nodeFrom.asExpr() = h.getValue().getChild(_) and nodeTo.asExpr() = h
    )
    or
    // 3c. Ternary `c ? a : b`: both branches flow to the result.
    exists(Php::ConditionalExpression c |
      (nodeFrom.asExpr() = c.getBody() or nodeFrom.asExpr() = c.getAlternative()) and
      nodeTo.asExpr() = c
    )
    or
    // 3d. Null-coalescing `a ?? b`: both operands flow to the result.
    exists(Php::BinaryExpression b |
      b.getOperator() = "??" and
      (nodeFrom.asExpr() = b.getLeft() or nodeFrom.asExpr() = b.getRight()) and
      nodeTo.asExpr() = b
    )
    or
    // 4. Array read: the array value taints a subscript of it (`$_GET` -> `$_GET['x']`).
    exists(Php::SubscriptExpression sub |
      nodeFrom.asExpr() = sub.getChild(0) and nodeTo.asExpr() = sub
    )
    or
    // 4b. Property read: a tainted object taints its properties (`$o` -> `$o->prop`).
    //     Covers `__get` magic reads (field-insensitive, recall-first).
    exists(Php::MemberAccessExpression m | nodeFrom.asExpr() = m.getObject() and nodeTo.asExpr() = m)
    or
    exists(Php::NullsafeMemberAccessExpression m |
      nodeFrom.asExpr() = m.getObject() and nodeTo.asExpr() = m
    )
    or
    // 4c. Getter / magic / fluent method: a tainted receiver taints the result of a call on it
    //     (`$o` -> `$o->getX()`, `$o->__call(...)`, `$o->whatever()`).
    exists(MethodCall c | nodeFrom.asExpr() = c.getReceiver() and nodeTo.asExpr() = c)
    or
    // 4d. Static property: `C::$p = v` taints every read of `C::$p` (keyed by class + name).
    exists(Php::ScopedPropertyAccessExpression w, Php::ScopedPropertyAccessExpression r, AssignExpr a |
      a.getLhs() = w and staticPropKey(w) = staticPropKey(r) and w != r and
      nodeFrom.asExpr() = a.getRhs() and nodeTo.asExpr() = r
    )
    or
    // 4e. Variable variables `$$name = v`: when `$name` resolves to a constant, taint the concrete
    //     variable `$<value>`; otherwise over-approximate to variable-variable reads in the file.
    exists(Php::DynamicVariableName w, AssignExpr a, VariableAccess read |
      a.getLhs() = w and
      read.getName() = resolvedStringValue(w.getChild()) and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = read
    )
    or
    exists(Php::DynamicVariableName w, Php::DynamicVariableName r, AssignExpr a |
      a.getLhs() = w and
      w.getLocation().getFile() = r.getLocation().getFile() and
      w != r and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = r
    )
    or
    // 5. Taint-propagating built-in call: argument taints the call result.
    exists(FunctionCall c |
      propagatingBuiltin(c.getName()) and
      nodeFrom.asExpr() = c.getAnArgument() and
      nodeTo.asExpr() = c
    )
    or
    // 6. `(string)` cast propagates taint.
    exists(CastExpr cast |
      cast.getTypeName() = ["string", "binary"] and
      nodeFrom.asExpr() = cast.getOperand() and
      nodeTo.asExpr() = cast
    )
    or
    // 7. Inter-procedural (by name): argument -> reads of the matching parameter in the callee.
    exists(FunctionCall c, Function f, int i, VariableAccess pRead |
      f.getName() = c.getName() and
      nodeFrom.asExpr() = c.getArgument(i) and
      f.getParameter(i).getName() = pRead.getName() and
      not isWrite(pRead) and
      f = enclosingFunction(pRead) and
      nodeTo.asExpr() = pRead
    )
    or
    // 8. Inter-procedural: a returned value flows to the call site.
    exists(FunctionCall c, Function f, ReturnStmt r |
      f.getName() = c.getName() and
      f = enclosingFunction(r) and
      nodeFrom.asExpr() = r.getValue() and
      nodeTo.asExpr() = c
    )
    or
    // 9. Method call (by name): argument -> reads of the matching parameter in the method body.
    //    Receiver types are not yet resolved, so all methods of that name are considered
    //    (over-approximate but sound for taint).
    exists(MethodCall c, Method m, int i, VariableAccess pRead |
      m.getName() = c.getMethodName() and
      nodeFrom.asExpr() = c.getArgument(i) and
      m.getParameter(i).getName() = pRead.getName() and
      not isWrite(pRead) and
      m = enclosingMethod(pRead) and
      nodeTo.asExpr() = pRead
    )
    or
    // 10. Method call: a returned value flows to the call site.
    exists(MethodCall c, Method m, ReturnStmt r |
      m.getName() = c.getMethodName() and
      m = enclosingMethod(r) and
      nodeFrom.asExpr() = r.getValue() and
      nodeTo.asExpr() = c
    )
  }

  /** Holds if taint reaches `node` from `source`, without passing through a non-propagated value. */
  private predicate taintReachesFrom(DataFlow::Node source, DataFlow::Node node) {
    isSource(source) and node = source
    or
    exists(DataFlow::Node mid | taintReachesFrom(source, mid) and taintStep(mid, node))
  }

  /** Holds if tainted data flows from `source` to the `kind` sink `sink`. */
  predicate hasTaintFlow(DataFlow::Node source, DataFlow::Node sink, string kind) {
    taintReachesFrom(source, sink) and isSink(sink, kind)
  }
}
