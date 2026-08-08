/** Shared taint sources and sinks for PHP security queries, on the interprocedural engine. */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.DataFlow
private import codeql.php.dataflow.internal.SsaImpl as SsaImpl
private import codeql.php.dataflow.internal.TypeInference as TI
import codeql.php.Concepts
import codeql.php.security.ModelExtensions

/** Holds if `n` is attacker-controlled input (request superglobals and common input helpers). */
predicate isRemoteSource(DataFlow::Node n) {
  n.asExpr().(VariableAccess).getName() =
    ["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "HTTP_RAW_POST_DATA"]
  // ($_ENV is process/server environment — NOT attacker-controlled by default; request-derived CGI vars
  //  live in $_SERVER, handled with the constant-key split below.)
  or
  // `$_SERVER` is a MIX: request-derived keys (`REQUEST_URI`, `QUERY_STRING`, `HTTP_*`, `PHP_SELF`,
  // `PATH_INFO`, …) are attacker-influenced, but `SCRIPT_FILENAME`/`DOCUMENT_ROOT`/`PWD`/`SERVER_ADDR`/…
  // are SERVER-controlled. Treating the whole array as remote floods file/path/include sinks — e.g. the
  // pervasive fixed-path bootstrap `require $_SERVER['SCRIPT_FILENAME'] . '/…/bootstrap.inc'`. Mirror the
  // `getenv()` split: a `$_SERVER` read is a source UNLESS it is subscripted with a constant
  // server-controlled key. Dynamic/absent keys and the bare array stay sources (conservative).
  exists(VariableAccess sv | sv.getName() = "_SERVER" and n.asExpr() = sv |
    not serverControlledServerRead(sv)
  )
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
  // methods (`__wakeup`/`__destruct`/`__unserialize`) is a remote source.
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
predicate isSanitizerGuardFunction(string name) { sanitizerGuardModel(name) }

/**
 * Holds if `g` is a call to a modelled sanitizer-guard validator, whether a global function
 * (`ctype_alnum($x)`), a STATIC method (`Validate::isUnsignedId($x)` — PrestaShop), or an instance
 * method (`$validator->isEmail($x)`). Guard names in `sanitizerGuardModel` are curated and distinctive,
 * so keying on the callee name across all three call kinds keeps false-negatives (an over-eager guard)
 * low while covering the OO validators that a function-only match missed.
 */
private predicate isSanitizerGuardCall(Call g) {
  isSanitizerGuardFunction([
      g.(FunctionCall).getName(), g.(StaticMethodCall).getMethodName(),
      g.(MethodCall).getMethodName()
    ])
}

/** Holds if `u` is a logical-NOT `!e`. */
private predicate isLogicalNot(Php::UnaryOpExpression u) { u.getOperator().toString() = "!" }

/**
 * Gets the number of logical-NOT operators between the guard call `g` and the condition root of `ifs`
 * (i.e. how many `!` wrap `g`). Its PARITY is the guard's polarity: even = the guard's truth controls the
 * THEN branch (`if (g($x))`); odd = it controls the ELSE branch / a negated early-exit (`if (!g($x))`).
 */
private int guardNegationCount(Call g, Php::IfStatement ifs) {
  isSanitizerGuardCall(g) and
  g.(Php::AstNode).getParent*() = ifs.getCondition() and
  result =
    count(Php::UnaryOpExpression u |
      isLogicalNot(u) and
      g.(Php::AstNode).getParent+() = u and
      u.(Php::AstNode).getParent*() = ifs.getCondition()
    )
}

/** Holds if statement `s` unconditionally leaves the current straight-line flow (return/throw/exit/…). */
private predicate stmtExits(Php::AstNode s) {
  s instanceof Php::ReturnStatement or
  s instanceof Php::ExitStatement or
  s instanceof Php::ContinueStatement or
  s instanceof Php::BreakStatement or
  s.(Php::ExpressionStatement).getChild() instanceof Php::ThrowExpression
}

/** Holds if the THEN body of `ifs` exits (a direct `return;`/`throw`/`exit`/`continue`/`break`). */
private predicate ifBodyExits(Php::IfStatement ifs) {
  stmtExits(ifs.getBody()) or
  stmtExits(ifs.getBody().(Php::CompoundStatement).getChild(_))
}

/** Gets the `i`-th ordered statement child of a straight-line block (`{…}` or the top-level program). */
private predicate orderedBlockChild(Php::AstNode blk, int i, Php::AstNode child) {
  child = blk.(Php::CompoundStatement).getChild(i)
  or
  child = blk.(Php::Program).getChild(i)
}

/**
 * Holds if `node` is inside `body` but NOT inside a nested callable (closure / arrow-fn / inner function /
 * method) declared within it. Prevents a parameter/variable read from being attributed to the wrong callable
 * when a nested lambda's own parameter SHADOWS the outer name (`function h(int $id){ array_map(function($id){
 * … $id … }, $x); }` — the closure's `$id` is not the outer scalar param / route param).
 */
private predicate notInNestedCallable(Php::AstNode node, Php::AstNode body) {
  node.getParent+() = body and
  not exists(Php::AstNode inner |
    node.getParent+() = inner and
    inner.getParent+() = body and
    (
      inner instanceof Php::AnonymousFunction or
      inner instanceof Php::ArrowFunction or
      inner instanceof Php::FunctionDefinition or
      inner instanceof Php::MethodDeclaration
    )
  )
}

/** Holds if the access path of `ref` is (re)assigned in a straight-line sibling statement of `blk` whose
 *  index is strictly between `lo` and `hi` — i.e. the value is re-tainted between a barrier and a later use. */
bindingset[lo, hi]
private predicate accessPathReassignedBetween(Php::AstNode blk, int lo, int hi, Expr ref) {
  exists(int k, Php::AstNode midStmt, Expr lhs |
    orderedBlockChild(blk, k, midStmt) and
    lo < k and
    k < hi and
    lhs.(Php::AstNode).getParent*() = midStmt and
    (
      lhs = any(Php::AssignmentExpression a).getLeft() or
      lhs = any(Php::AugmentedAssignmentExpression a).getLeft() or
      lhs = any(Php::ReferenceAssignmentExpression a).getLeft()
    ) and
    sameAccessPath(lhs, ref)
  )
}

/**
 * Holds if `use` is (inside) a statement that comes AFTER `ifs` in the same straight-line block, with NO
 * reassignment of `checked`'s access path in between (a reassignment re-taints the value, so an early-exit
 * guard on the OLD value no longer protects the read).
 */
private predicate readAfterInSameBlock(Php::IfStatement ifs, Expr use, Expr checked) {
  exists(Php::AstNode blk, int i, int j, Php::AstNode afterStmt |
    orderedBlockChild(blk, i, ifs) and
    orderedBlockChild(blk, j, afterStmt) and
    j > i and
    use.(Php::AstNode).getParent*() = afterStmt and
    not accessPathReassignedBetween(blk, i, j, checked)
  )
}

/** Holds if `g` sits under a logical operator in `ops` within the `if` condition. */
bindingset[ops]
private predicate guardUnderConnective(Call g, Php::IfStatement ifs, string ops) {
  exists(BinaryOperation b |
    b.getOperator() = ops and
    g.(Php::AstNode).getParent+() = b and
    b.(Php::AstNode).getParent*() = ifs.getCondition()
  )
}

/**
 * Holds if a logical connective makes the guard UNSOUND for the branch it would clear. The rule is
 * POLARITY-DEPENDENT (De Morgan):
 *  - positive guard, read in the THEN branch (entered when the condition is TRUE): an `||`/`or` sibling means
 *    the guard may be false there → reject `||`/`or`/`xor`. An `&&` sibling is still guaranteed true → allowed.
 *  - negated guard, read in the ELSE branch or the fall-through of a negated early-exit (entered when the
 *    condition is FALSE): De Morgan flips it — an `&&`/`and` sibling means the guard may be false there →
 *    reject `&&`/`and`/`xor`. An `||`/`or` sibling is fine.
 */
bindingset[neg]
private predicate guardConnectiveUnsound(Call g, Php::IfStatement ifs, int neg) {
  neg % 2 = 0 and guardUnderConnective(g, ifs, ["||", "or", "xor"])
  or
  neg % 2 = 1 and guardUnderConnective(g, ifs, ["&&", "and", "xor"])
}

/**
 * Holds if `n` is a read of a variable validated by a sanitizer guard on the branch it actually controls.
 * POLARITY-AWARE (the guard's `!`-parity decides then vs else) + EARLY-EXIT aware:
 *   - `if (g($x))      { … $x … }`             — positive guard, THEN branch is safe;
 *   - `if (!g($x)) {…} else { … $x … }`        — negated guard, ELSE branch is safe;
 *   - `if (!g($x)) return;  … $x …`            — negated early-exit, the fall-through is safe.
 * The two previously-mishandled cases — a negated guard with the read in the THEN branch (false NEGATIVE:
 * `if(!ctype_digit($id)){query($id);}`) and a negated early-exit read reported as unguarded (false
 * POSITIVE: `if(!g($x))return; sink($x);`) — are now correct. A CUSTOM/unknown guard is still NOT matched,
 * so its path stays reported (recall-first). SOUNDNESS: the read is cleared ONLY when the guard is the sole
 * controlling term (no `&&`/`||` connective — `guardUnderLogicalConnective`) and the value is NOT reassigned
 * between the guard and the read (`accessPathReassignedBetween`, in the early-exit arm).
 */
predicate isGuardedRead(DataFlow::Node n) { isGuardedReadByName(n, _) }

/** Gets the callee (short) name of a guard call, across function / static-method / instance-method forms. */
private string guardCallName(Call g) {
  result =
    [
      g.(FunctionCall).getName(), g.(StaticMethodCall).getMethodName(),
      g.(MethodCall).getMethodName()
    ]
}

/**
 * As `isGuardedRead`, but also binds the guard's callee `guardName`. Lets a consumer (e.g. the IDOR taint
 * engine) reuse the sound polarity/early-exit/connective/reassignment logic while restricting to a specific
 * class of guards (numeric validators don't stop IDOR, so it removes ONLY those, keeping whitelist guards).
 */
predicate isGuardedReadByName(DataFlow::Node n, string guardName) {
  exists(Php::IfStatement ifs, Call g, Expr checked, Expr use, int neg |
    guardName = guardCallName(g) and
    neg = guardNegationCount(g, ifs) and
    not guardConnectiveUnsound(g, ifs, neg) and
    checked = g.getAnArgument() and
    sameAccessPath(checked, use) and
    use != checked and
    n.asExpr() = use and
    (
      // positive polarity (even `!`s): read guarded in the THEN branch
      neg % 2 = 0 and use.(Php::AstNode).getParent*() = ifs.getBody()
      or
      // negative polarity (odd `!`s): read guarded in the ELSE branch
      neg % 2 = 1 and use.(Php::AstNode).getParent*() = ifs.getAlternative(_)
      or
      // negated early-exit `if (!g($x)) return;` — the fall-through past the `if` is guarded (unless the
      // value is reassigned in between, which `readAfterInSameBlock` rejects).
      neg % 2 = 1 and
      ifBodyExits(ifs) and
      not exists(ifs.getAlternative(_)) and
      readAfterInSameBlock(ifs, use, checked)
    )
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
  // Method sanitizers (`$pdo->quote()`, `$db->escape()`, …) are DATA — `sanitizerModel` method rows.
  // Numeric/bool CASTS `(int)$x` are handled by `NumericCastSanitizer` below (which also covers `(real)`).
  // `array_map('intval', (array)$x)` — an elementwise scalar-coercion callback makes EVERY element
  // numeric, so the resulting array (and any implode/join of it) is safe. Cuts the classic "coerce the
  // array to ints before use" false path — the array/type-juggling case where a value is turned into a
  // guaranteed-numeric list. The callback is read as a string literal (`'intval'`), matching the
  // dynamic-callback dispatch already used for array_map sinks.
  exists(FunctionCall c |
    c.getName() = "array_map" and
    // callback given as a string literal `'intval'` (opt. leading `\`) OR a PHP 8.1 first-class callable
    // `array_map(intval(...), $x)`.
    [
      c.getArgument(0).(StringLiteral).getValue().regexpReplaceAll("^\\\\", ""),
      firstClassCallableName(c.getArgument(0))
    ] = ["intval", "absint", "floatval", "boolval", "doubleval"] and
    n.asExpr() = c
  )
}

/**
 * Maps a dangerous built-in function name to the vulnerability `kind` its arguments expose — read from
 * the `sinkModel` DATA (`ext/php-builtins.model.yml`), NOT a hardcoded QL list (Phase C). Used by the
 * dynamic-dispatch sinks below (`$fn(...)`, `call_user_func('system', …)`), where the callee name is
 * resolved structurally in QL and then looked up here.
 */
string sinkFunctionKind(string fname) { sinkModel("function", fname, -1, result) }

/**
 * Holds if `sv` (a `$_SERVER` variable access) is read via a constant, clearly SERVER-controlled key —
 * filesystem/identity CGI variables the client cannot influence. These must NOT be remote sources (they
 * flood file/path/include sinks). Request-derived keys (`REQUEST_URI`, `QUERY_STRING`, `HTTP_*`,
 * `PHP_SELF`, `PATH_INFO`, `SERVER_NAME`, …) are deliberately excluded from this list so they stay sources.
 */
private predicate serverControlledServerRead(VariableAccess sv) {
  sv.getName() = "_SERVER" and
  exists(Php::SubscriptExpression sub, string k |
    sub.getChild(0) = sv.(Php::AstNode) and
    k = sub.getChild(1).(Php::String).getChild(_).(Php::StringContent).getValue().toUpperCase() and
    k =
      [
        "SCRIPT_FILENAME", "DOCUMENT_ROOT", "CONTEXT_DOCUMENT_ROOT", "PWD", "SERVER_ADDR",
        "SERVER_SOFTWARE", "SERVER_ADMIN", "SERVER_SIGNATURE", "GATEWAY_INTERFACE", "SERVER_PORT",
        "SERVER_PROTOCOL", "CONTEXT_PREFIX", "REQUEST_TIME", "REQUEST_TIME_FLOAT"
      ]
  )
}

/** Gets the constant string value of a single- or double-quoted string literal `e`. */
private string constantStringValue(Expr e) {
  e.(Php::String).getChild(_).(Php::StringContent).getValue() = result
  or
  e.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue() = result
}

/**
 * Holds when `e` is (or a `A | B` bit-or combination containing) an unsafe libxml flag — the entity /
 * DTD-loading flags that re-enable XXE in an otherwise safe-by-default modern libxml.
 */
private predicate unsafeLibxmlFlag(Php::AstNode e) {
  e.(Php::Name).getValue() = ["LIBXML_NOENT", "LIBXML_DTDLOAD", "LIBXML_DTDATTR", "LIBXML_DTDVALID"]
  or
  unsafeLibxmlFlag(e.(Php::BinaryExpression).getLeft())
  or
  unsafeLibxmlFlag(e.(Php::BinaryExpression).getRight())
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

/** Gets the method name of a 2-element array callable `[$recv, 'm']` / `['C', 'm']`. */
private string arrayCallableMethodName(Php::ArrayCreationExpression arr) {
  result =
    arr.getChild(1).(Php::ArrayElementInitializer).getChild(0).(StringLiteral).getValue()
}

/** Resolves an `add_filter(hook, $cb)` callback expression to its callable — an `[$this,'m']`/`['C','m']`
 *  array-callable METHOD or an inline closure. */
private AstNode wpQueryFilterCallback(Expr arg) {
  result = TI::arrayCallableMethod(arg)
  or
  arg instanceof Php::AnonymousFunction and result = arg
}

/** Gets the body of a resolved query-filter callback (to locate its `return` statements). */
private AstNode wpQueryFilterBody(AstNode cb) {
  result = cb.(Php::MethodDeclaration).getBody()
  or
  result = cb.(Php::AnonymousFunction).getBody()
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
  // A known-dangerous function named (as a constant string) as the CALLBACK of a higher-order
  // built-in — `array_map('system', $x)`, `call_user_func('system', $x)`, `usort($x, 'system')` —
  // so the data argument(s) flow into that sink. Function + positions are DATA (`callbackModel`).
  exists(FunctionCall c, int cb, int da, int k |
    callbackModel(c.getName(), cb, da) and
    kind = sinkFunctionKind(constantStringValue(c.getArgument(cb))) and
    k >= da and
    k != cb and
    n.asExpr() = c.getArgument(k)
  )
  or
  // Array-callable METHOD dispatch: `call_user_func([$obj, 'query'], $sql)` / `array_map([$o,'m'], …)`
  // where the callback names a MODELED sink method — the mirror of the string-callback sink above. Scoped
  // to sink-method names (the same genericity as the direct `$obj->query()` sink, no extra FP), so a sink
  // reached through this callable form is not silently lost.
  exists(FunctionCall c, int cb, int da, int k, string m, int i |
    callbackModel(c.getName(), cb, da) and
    m = arrayCallableMethodName(c.getArgument(cb)) and
    sinkModel("method", m, i, kind) and
    k >= da and
    k != cb and
    (i = -1 or k = da + i) and
    n.asExpr() = c.getArgument(k)
  )
  or
  // NOTE: raw SQL query METHODS (PDO/mysqli `query`/`exec`, Laravel `whereRaw`, Doctrine
  // `executeQuery`, …) are DATA — `sinkModel` method rows in the framework `ext/*.model.yml`
  // (Phase C), applied by `DataSink`.
  exists(EchoStmt e | n.asExpr() = e.getAnOperand() and kind = "reflected XSS")
  or
  // `<?= $x ?>` short-echo tag — the workhorse of PHP templates (.phtml, WordPress/Magento themes).
  // tree-sitter models it NOT as an `echo` but as a `<?=` PhpTag token immediately followed by an
  // ExpressionStatement, so the echoed expression is a `reflected XSS` sink.
  exists(Php::ExpressionStatement es, Php::PhpTag t |
    t.getValue() = "<?=" and
    t.getLocation().getEndLine() = es.getLocation().getStartLine() and
    t.getLocation().getEndColumn() <= es.getLocation().getStartColumn() and
    es.getLocation().getStartColumn() - t.getLocation().getEndColumn() <= 3 and
    n.asExpr() = es.getChild() and
    kind = "reflected XSS"
  )
  or
  // `print $x` / `print($x)` is a language construct (PrintIntrinsic), not a function call.
  exists(Php::PrintIntrinsic p | n.asExpr() = p.getChild() and kind = "reflected XSS")
  or
  // `include $x` / `require $x` (language construct, not a function call) — file inclusion.
  exists(IncludeExpr inc | n.asExpr() = inc.getPath() and kind = "file inclusion")
  or
  // WordPress query-clause filters: `add_filter('posts_where'|'posts_join'|'posts_orderby'|'posts_groupby'
  // |'posts_clauses', $cb)` — WP_Query concatenates the callback's RETURN string straight into the SQL it
  // runs, so a tainted return (request input built into the WHERE/ORDER clause, often only esc_like'd) is
  // SQL injection. The actual $wpdb->get_results is in WP core, so the callback's returned expression is
  // the sink (a whole class: "load more"/search plugins, e.g. tlp-team CVE-2025-14124). The hook names are
  // fixed WP-core constants (generalizable, not per-app).
  exists(FunctionCall addFilter, AstNode cb, ReturnStmt ret |
    addFilter.getName() = "add_filter" and
    addFilter.getArgument(0).(StringLiteral).getValue() =
      [
        "posts_where", "posts_where_request", "posts_join", "posts_join_request", "posts_orderby",
        "posts_groupby", "posts_clauses", "posts_clauses_request"
      ] and
    cb = wpQueryFilterCallback(addFilter.getArgument(1)) and
    ret.(Php::AstNode).getParent+() = wpQueryFilterBody(cb) and
    n.asExpr() = ret.getValue() and
    kind = "SQL injection"
  )
  or
  // `header('Location: '.$url)` is an open-redirect sink — but ONLY for a `Location:` header, not
  // `header('X-Request-Uri: '.$x)`. Fire when the argument carries a `Location:` string literal.
  exists(FunctionCall c |
    c.getName() = "header" and
    exists(Php::StringContent sc |
      sc.(Php::AstNode).getParent+() = c.getArgument(0) and
      sc.getValue().toLowerCase().matches("location:%")
    ) and
    n.asExpr() = c.getArgument(0) and
    kind = "open redirect"
  )
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
  or
  // Laravel unsafe validator: `Rule::unique(...)->ignore($userInput)` / `Rule::exists(...)->ignore(...)`
  // — a user-controlled `ignore()` argument lets an attacker exclude an arbitrary row, bypassing the
  // uniqueness/existence check (mass-assignment-style validation bypass).
  exists(Php::MemberCallExpression c, Php::ScopedCallExpression rule |
    c.getName().(Php::Name).getValue() = "ignore" and
    rule = c.getObject() and
    rule.getName().(Php::Name).getValue() = ["unique", "exists"] and
    n.asExpr() = c.getArguments().getChild(_).(Php::Argument).getChild() and
    kind = "validation bypass"
  )
  or
  // Laravel Storage facade accessed through a disk: `Storage::disk('x')->path($p)` / `->get` / `->put` /
  // `->download` / `->delete` / `->readStream`. The `disk()` factory returns a `Filesystem` whose type
  // does not resolve (framework code), so the plain `typedSinkModel` on `Storage` cannot fire; the path
  // argument is matched structurally on the recognisable `Storage::disk(...)` receiver instead — scoped
  // to that facade, so no generic `->path()` false positives (CVE-2024-42485).
  exists(MethodCall c, StaticMethodCall disk |
    disk = c.getReceiver() and
    disk.getMethodName() = "disk" and
    disk.getTargetName() = "Storage" and
    // Same Laravel Filesystem contract as the app('files') service below — keep the dangerous-method set
    // aligned. A traversal in ->deleteDirectory / ->move / ->copy is exactly as bad as in ->delete
    // (Voyager media-manager CVE-2024-55415 deletes folders via Storage::disk()->deleteDirectory($p)).
    c.getMethodName() =
      [
        "path", "get", "put", "putFile", "putFileAs", "download", "delete", "deleteDirectory", "readStream",
        "prepend", "append", "move", "copy", "makeDirectory", "cleanDirectory", "replace"
      ] and
    n.asExpr() = c.getArgument(0) and
    kind = "path traversal"
  )
  or
  // PrestaShop DB facade: `Db::getInstance()->getValue($sql)` / `->getRow` / `->executeS` / `->execute`.
  // `getValue`/`getRow` are far too common to model as bare method sinks, and `Db::getInstance()` is a
  // static factory whose return type does not resolve — so, exactly like the Storage facade above, the
  // query argument is matched structurally on the recognisable `Db::getInstance()` receiver, scoped to
  // that facade (no generic `->getValue()` false positives) (CVE-2024-28391).
  exists(MethodCall c, StaticMethodCall inst |
    inst = c.getReceiver() and
    inst.getMethodName() = "getInstance" and
    inst.getTargetName() = "Db" and
    c.getMethodName() = ["getValue", "getRow", "executeS", "ExecuteS", "execute", "query"] and
    n.asExpr() = c.getArgument(0) and
    kind = "SQL injection"
  )
  or
  // PrestaShop Db write helpers: `Db::getInstance()->delete($table, $where)` /
  // `->update($table, $data, $where)` concatenate the WHERE clause RAW into the SQL
  // (classes/db/Db.php: `' WHERE ' . $where`) — the row VALUES are pSQL-escaped by callers but the WHERE
  // string is not, so a tainted WHERE is SQLi. Scoped to the recognisable Db::getInstance() receiver like
  // the raw-query methods above. delete()'s WHERE is arg 1; update()'s WHERE is arg 2.
  exists(MethodCall c, StaticMethodCall inst |
    inst = c.getReceiver() and
    inst.getMethodName() = "getInstance" and
    inst.getTargetName() = "Db" and
    (
      c.getMethodName() = "delete" and n.asExpr() = c.getArgument(1)
      or
      c.getMethodName() = "update" and n.asExpr() = c.getArgument(2)
    ) and
    kind = "SQL injection"
  )
  or
  // Laravel filesystem via the `app('files')` service locator: `app('files')->delete($path)` / `->get` /
  // `->put` / … . Same rationale as the Storage/Db facades — the helper returns a `Filesystem` whose type
  // does not resolve, so the path argument is matched structurally on the recognisable `app('files')`
  // receiver, scoped to that service string (no generic `->delete()` false positives) (CVE-2024-55415).
  exists(MethodCall c, FunctionCall app |
    app = c.getReceiver() and
    app.getName() = "app" and
    constantStringValue(app.getArgument(0)) = "files" and
    c.getMethodName() =
      [
        "delete", "get", "put", "append", "prepend", "move", "copy", "makeDirectory", "deleteDirectory",
        "cleanDirectory", "replace"
      ] and
    n.asExpr() = c.getArgument(0) and
    kind = "path traversal"
  )
  or
  // XXE — modern libxml disables external-entity / DTD loading BY DEFAULT, so an XML parse is only
  // dangerous when an unsafe libxml flag (LIBXML_NOENT / a DTD-loading flag) is explicitly passed. We
  // therefore flag the parsed-string argument ONLY when such a flag appears in the call, which keeps the
  // safe-default majority free of false positives. Covers CVE-2023-38490 (Kirby) and the SAML2
  // DOMDocument::loadXML class.
  exists(FunctionCall c |
    c.getName() = ["simplexml_load_string", "simplexml_load_file"] and
    unsafeLibxmlFlag(c.getAnArgument()) and
    n.asExpr() = c.getArgument(0) and
    kind = "xxe"
  )
  or
  exists(MethodCall c |
    c.getMethodName() = ["loadXML", "load"] and  // NOT loadHTML — HTML parsing does not expand XML entities
    unsafeLibxmlFlag(c.getAnArgument()) and
    n.asExpr() = c.getArgument(0) and
    kind = "xxe"
  )
  or
  // expat (`xml_parse`) EXPANDS external entities BY DEFAULT — no flag gate; the parsed data (arg 1) is the
  // sink whenever it is attacker-controlled. Also `libxml_disable_entity_loader(false)` and the property
  // forms `DOMDocument::$substituteEntities/$resolveExternals = true` re-enable the unsafe behaviour, so a
  // subsequent parse of a tainted string is dangerous even without an explicit LIBXML_NOENT flag.
  exists(FunctionCall c |
    c.getName() = "xml_parse" and
    n.asExpr() = c.getArgument(1) and
    kind = "xxe"
  )
  or
  // Dynamic class instantiation `new $c(...)` / `new $arr['k'](...)` where the CLASS NAME is
  // attacker-controlled — arbitrary object instantiation (autoloader / constructor side effects).
  exists(Php::ObjectCreationExpression oc |
    (
      oc.getChild(0) instanceof Php::VariableName or
      oc.getChild(0) instanceof Php::SubscriptExpression
    ) and
    n.asExpr() = oc.getChild(0) and
    kind = "code injection"
  )
  or
  // A tainted CALLBACK argument to a higher-order built-in (`usort($a, $_GET['f'])`,
  // `array_map($_GET['f'], $a)`, `call_user_func($_GET['f'])`) lets the attacker name the function
  // that runs — arbitrary code execution. Callback position depends on the built-in.
  exists(FunctionCall c, int cb |
    callbackModel(c.getName(), cb, _) and
    n.asExpr() = c.getArgument(cb) and
    kind = "code injection"
  )
  or
  // `preg_replace('/…/e', $replacement, $subject)` — the deprecated `e` (PREG_REPLACE_EVAL) modifier
  // executes the REPLACEMENT (arg 1) as PHP code, first expanding backreferences from the SUBJECT
  // (arg 2). A classic PHP<7 RCE (still shipped in the many legacy D5/6/7 modules in the wild). When
  // the pattern (arg 0) is a constant string whose trailing modifier flags include `e`, both the
  // replacement and the subject are code-injection sinks. Detected structurally on the constant
  // pattern: after a PCRE delimiter, only valid modifier letters, one of them `e`.
  exists(FunctionCall c |
    c.getName() = "preg_replace" and
    // Closing delimiter then PCRE modifier flags including `e`. The class covers both single-char
    // delimiters (`/ # ~ ! @ % | , + = : .`) and the CLOSING half of paired delimiters (`) } ] >`),
    // so `preg_replace('(pat)e', …)` / `preg_replace('{pat}e', …)` are caught (previously missed).
    constantStringValue(c.getArgument(0))
        .regexpMatch("(?s).*[/#~!@%|,+=:.)\\]}>][imsxuADSUXJ]*e[imsxuADSUXJ]*") and
    n.asExpr() = [c.getArgument(1), c.getArgument(2)] and
    kind = "code injection"
  )
}

/**
 * A class-qualified method source (`typedSourceModel`): `$request->get()` is a source only when the
 * receiver's inferred class matches, so `$someOtherObject->get()` is not. Re-arms the framework request
 * accessors that a bare method name could not model without false positives.
 */
/**
 * Holds if the receiver `recv`'s inferred class is `cls`, OR has `cls` as a (transitive) ancestor
 * (superclass or implemented interface), OR its written type-name is `cls`. The ancestor arm lets a
 * model keyed on a framework BASE class also fire on its subclasses — the dominant real-world shape
 * (a MODX processor `class FooProcessor extends Processor`, a Symfony controller extending
 * `AbstractController`, a request subclass, …). Class-scoped model rows already use specific names, so
 * broadening to subclasses adds true positives without the FP flood a bare method name would cause.
 */
private predicate receiverIsClass(Expr recv, string cls) {
  TI::exprClass(recv).getName() = cls
  or
  TI::exprClass(recv).getAnAncestor().getName() = cls
  or
  TI::exprTypeName(recv) = cls
  or
  // Yii / Craft application request component: `Yii::$app->request` / `Craft::$app->request`. The request
  // is a property on the application reached through a static `::$app` property, so its type never infers
  // — treat a `->request` member access reached through a `Yii::`/`Craft::` static-property object as the
  // framework `Request`, re-arming the class-scoped `["Request", get/post/…]` accessors. Scoped to the two
  // real application classes (not any `::$prop`) so an unrelated `Foo::$bar->request` is not a source.
  cls = "Request" and
  exists(Php::MemberAccessExpression req, Php::ScopedPropertyAccessExpression app |
    req = recv and
    req.getName().(Php::Name).getValue() = "request" and
    app = req.getObject() and
    app.getScope().toString() = ["Yii", "Craft"]
  )
}

private class TypedRemoteSource extends RemoteFlowSource {
  string sourceType;

  TypedRemoteSource() {
    exists(MethodCall c, string cls, string m |
      typedSourceModel(cls, m, sourceType) and
      c.getMethodName() = m and
      receiverIsClass(c.getReceiver(), cls) and
      this.asExpr() = c
    )
  }

  override string getSourceType() { result = sourceType }
}

/**
 * A class-qualified STATIC method source (`typedSourceModel` reused for static calls): `Input::post()`
 * (Contao) is a source only when the scope qualifier is exactly the named class, so a bare `post`/`get`
 * cannot FP across unrelated classes. The qualifier is known syntactically (`getTargetName()`), so this
 * needs no type inference and works even when the class lives in an un-extracted `vendor/`. Because both
 * the class name AND the method must match, `Model::all()` never matches a `["Request","all",…]` entry.
 */
private class TypedStaticRemoteSource extends RemoteFlowSource {
  string sourceType;

  TypedStaticRemoteSource() {
    exists(StaticMethodCall c, string cls, string m |
      typedSourceModel(cls, m, sourceType) and
      c.getTargetName() = cls and
      c.getMethodName() = m and
      this.asExpr() = c
    )
  }

  override string getSourceType() { result = sourceType }
}

/**
 * A property access on a Laravel `Request` (`$request->field`) — the framework's `__get` returns the
 * corresponding input value, so any non-method property read of a Request-typed receiver is user input.
 * A few framework-internal names (the authenticated user, the route/session objects) are excluded.
 */
private class RequestPropertySource extends RemoteFlowSource {
  RequestPropertySource() {
    exists(Php::MemberAccessExpression ma |
      (TI::exprClass(ma.getObject()).getName() = "Request" or TI::exprTypeName(ma.getObject()) = "Request") and
      // Only EXTERNAL reads (`$request->field`) — not `$this->prop` inside the Request class itself, which
      // is internal storage, and not the framework-internal property names.
      not ma.getObject().(Php::VariableName).getChild().getValue() = "this" and
      not ma.getName().(Php::Name).getValue() = ["user", "route", "session", "auth", "server", "headers"] and
      this.asExpr() = ma
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * A subscript read on a `WP_REST_Request` — `$request['author_exclude']`. `WP_REST_Request implements
 * ArrayAccess`, so `$request[$key]` desugars to `offsetGet($key)`, exactly equivalent to the modelled
 * `$request->get_param($key)`. WP core's own REST controllers read params THIS way — the parameter-
 * mapping loop `$args[$wp_param] = $request[$api_param]` in `WP_REST_Posts_Controller::get_items()` —
 * so modelling only the `get_*` methods (`typedSourceModel`) missed this whole entry form. That is the
 * source half of the WP-core `author__not_in` SQLi (CVE-2026-63030). Type-gated on the receiver, like
 * `TypedRemoteSource`, so an unrelated `$x[$k]` is not a source.
 */
private class RestRequestSubscriptSource extends RemoteFlowSource {
  RestRequestSubscriptSource() {
    exists(ArrayAccess aa |
      (
        TI::exprClass(aa.getArray()).getName() = "WP_REST_Request" or
        TI::exprTypeName(aa.getArray()) = "WP_REST_Request"
      ) and
      this.asExpr() = aa
    )
  }

  override string getSourceType() { result = "wordpress-request" }
}

/**
 * Drupal 7's array-shaped form state: `$form_state['values'][...]` / `['input'][...]` hold the
 * user-submitted form data (the D7 analogue of the D8 `FormStateInterface::getValue()` accessor). Matched
 * structurally on the well-known `$form_state` variable + `values`/`input` key so the subscripted element
 * is user input (e.g. CVE-2024-13297: `unserialize($form_state['values']['user_headers'])`).
 */
private class DrupalFormStateArraySource extends RemoteFlowSource {
  DrupalFormStateArraySource() {
    exists(Php::SubscriptExpression sub |
      sub.getChild(0).(VariableAccess).getName() = "form_state" and
      sub.getChild(1).(Php::String).getChild(_).(Php::StringContent).getValue() =
        ["values", "input", "user_input"] and
      this.asExpr() = sub
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * The Symfony/Drupal request-bag idiom: `$request->query->get('x')`, `$request->request->all()`,
 * `$request->cookies->get(...)`, etc. The `query`/`request`/`attributes`/`cookies`/`files` properties of
 * an HttpFoundation `Request` are `InputBag`/`ParameterBag`s whose accessors return user input. The bag
 * is reached through an intermediate property whose type does not resolve, so this is matched
 * structurally: a `get`/`all`/… call on a `<bag>` property of a `Request`-typed receiver.
 */
/**
 * Holds if `e` is (evaluates to) an HttpFoundation `Request`. Type-resolution covers a type-hinted
 * `Request $request` var, but the request is very often obtained from a FACTORY whose return type does
 * not flow through inference: Drupal's `\Drupal::request()`, a Symfony controller's `$this->getRequest()`,
 * or a `RequestStack`'s `->getCurrentRequest()`/`getMainRequest()`/`getMasterRequest()`. Those getter
 * names are distinctive enough to accept directly, which re-arms the whole `->query->get()` bag idiom on
 * factory-obtained requests (Drupal D8+ SQLi/XSS were entirely missed without this).
 */
private predicate isRequestExpr(Expr e) {
  TI::exprClass(e).getName() = "Request"
  or
  TI::exprTypeName(e) = "Request"
  or
  e.(MethodCall).getMethodName() = ["getRequest", "getCurrentRequest", "getMainRequest", "getMasterRequest"]
  or
  e.(StaticMethodCall).getTargetName() = "Drupal" and e.(StaticMethodCall).getMethodName() = "request"
}

private class SymfonyBagSource extends RemoteFlowSource {
  SymfonyBagSource() {
    exists(Php::MemberCallExpression get, Php::MemberAccessExpression bag |
      get.getObject() = bag and
      bag.getName().(Php::Name).getValue() =
        ["query", "request", "attributes", "cookies", "files"] and
      isRequestExpr(bag.getObject()) and
      // NB: getInt/getBoolean/getAlpha/getAlnum/getDigits coerce or charset-restrict to a non-injectable
      // value (they are SANITIZERS elsewhere, e.g. joomla/xoops getInt) — only the raw/free-form accessors
      // are sources. Listing the coercing getters here was the exact FP the model-level fix (T1-6) removed.
      get.getName().(Php::Name).getValue() = ["get", "all", "getString", "filter"] and
      this.asExpr() = get
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * `getenv('HTTP_…')` and the request-derived CGI variables are user input, but `getenv('TEMP'/'PATH'/
 * 'HOME'/…)` are SERVER-controlled and must not be sources — treating every `getenv()` as remote floods
 * file/path sinks (e.g. a backup plugin building temp paths from `getenv('TEMP')`). A dynamic or absent
 * key is treated conservatively as a source (it could resolve to an `HTTP_*` variable).
 */
private class GetenvSource extends RemoteFlowSource {
  GetenvSource() {
    exists(FunctionCall c | c.getName() = "getenv" and this.asExpr() = c |
      // dynamic / absent / non-constant key → conservative (it could resolve to an `HTTP_*` variable)
      not exists(constantStringValue(c.getArgument(0)))
      or
      exists(string k | k = constantStringValue(c.getArgument(0)).toUpperCase() |
        k.matches("HTTP\\_%")
        or
        k =
          [
            "QUERY_STRING", "REQUEST_URI", "REQUEST_METHOD", "PATH_INFO", "PATH_TRANSLATED",
            "CONTENT_TYPE", "CONTENT_LENGTH", "PHP_AUTH_USER", "PHP_AUTH_PW", "PHP_AUTH_DIGEST", "AUTH_TYPE"
          ]
      )
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * Dolibarr `GETPOST(name, type, …)` request accessor. The 2nd arg selects a sanitiser, but only the
 * NUMERIC/alphanumeric coercions (`int`/`intcomma`/`aZ09`/`aZ`) make the value SQL-safe. The HTML filters
 * (`restricthtml`/`nohtml`/`alphanohtml`/`alpha`) strip tags but do NOT escape quotes, so the value is
 * still an injection source for SQL/command/path — modelling them as fully-safe (the previous behaviour)
 * hid a whole class of Dolibarr SQLi. So GETPOST is a source UNLESS the type is a genuine SQL-safe coercion;
 * the HTML types are additionally an XSS barrier below (kind-aware: raw for SQL, safe for XSS).
 */
private string getpostSqlSafeType() {
  result = ["int", "integer", "intcomma", "aZ09", "aZ09comma", "aZ"]
}

private string getpostHtmlType() {
  result = ["restricthtml", "restricthtmlallowclass", "nohtml", "alphanohtml", "alpha"]
}

private class GetpostSource extends RemoteFlowSource {
  GetpostSource() {
    exists(FunctionCall c | c.getName() = "GETPOST" and this.asExpr() = c |
      not exists(c.getArgument(1))
      or
      // fires unless the type arg is a constant SQL-safe coercion (a dynamic/non-constant/INTERPOLATED
      // type is treated conservatively as a source — `constStringText` rejects interpolation, so
      // `GETPOST('id', "int$suffix")` is NOT mistaken for the SQL-safe literal 'int').
      not constStringText(c.getArgument(1)) = getpostSqlSafeType()
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * `GETPOST(name, 'restricthtml'|'nohtml'|'alphanohtml'|'alpha')` strips HTML/scripts, so the value is
 * XSS-safe even though it stays a SQL source (above). Barriering XSS at the source node suppresses the XSS
 * finding while the SQL/command/path flow proceeds — the kind-aware half of the Dolibarr GETPOST fix.
 */
private class GetpostHtmlXssBarrier extends XssSanitizer {
  GetpostHtmlXssBarrier() {
    exists(FunctionCall c |
      c.getName() = "GETPOST" and
      constStringText(c.getArgument(1)) = getpostHtmlType() and
      this.asExpr() = c
    )
  }
}

/**
 * `file_get_contents('php://input')` — the raw HTTP request body. REST/webhook/JSON-API handlers read
 * user input this way, so the call result is a remote source. Keyed on the literal `php://input` argument
 * (NOT `file_get_contents` in general, which is an ordinary file read), so it never fires elsewhere.
 */
private class PhpInputSource extends RemoteFlowSource {
  PhpInputSource() {
    exists(FunctionCall c |
      c.getName() = "file_get_contents" and
      constantStringValue(c.getArgument(0)) = "php://input" and
      this.asExpr() = c
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * OpenCart request: `$this->request->get['x']` / `->post` / `->cookie` / `->request`. The Request object's
 * public arrays are populated from the superglobals. Scoped to the `(...->request)->{get,post,cookie,
 * request}[...]` chain so the generic property names never fire outside that idiom.
 */
private class OpenCartRequestSource extends RemoteFlowSource {
  OpenCartRequestSource() {
    exists(
      Php::SubscriptExpression sub, Php::MemberAccessExpression prop, Php::MemberAccessExpression req
    |
      prop = sub.getChild(0) and
      prop.getName().(Php::Name).getValue() = ["get", "post", "cookie", "server", "files", "request"] and
      req = prop.getObject() and
      req.getName().(Php::Name).getValue() = "request" and
      this.asExpr() = sub
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * ProcessWire request: `$input->get->name` / `$input->post->x` / `$input->cookie->x` (and the
 * `$this->input->…` form used inside Wire classes). `WireInput::__get` returns a `WireInputData` whose
 * own `__get` reads the parsed GET/POST/COOKIE array, so the idiomatic PW read is a PROPERTY CHAIN, not
 * a call — `typedSourceModel` covers only the `$input->get('x')` method form, leaving this whole idiom
 * unmodelled. Scoped to the `(input)->{get,post,cookie,whitelist}->X` chain so the generic property
 * names never fire outside it. Same shape as the OpenCart source above (array-access there, chain here).
 */
private class ProcessWireRequestSource extends RemoteFlowSource {
  ProcessWireRequestSource() {
    exists(Php::MemberAccessExpression outer, Php::MemberAccessExpression bag |
      outer.getObject() = bag and
      bag.getName().(Php::Name).getValue() = ["get", "post", "cookie", "whitelist"] and
      (
        bag.getObject().(Php::VariableName).getChild().getValue() = "input"
        or
        bag.getObject().(Php::MemberAccessExpression).getName().(Php::Name).getValue() = "input"
      ) and
      this.asExpr() = outer
    )
  }

  override string getSourceType() { result = "remote" }
}

/**
 * A class-scoped sink (`typedSinkModel`): an argument is a sink only when the call's receiver type (for
 * `$obj->m()`) or static scope (for `C::m()`) is the named class — so generic method names like
 * `get`/`query`/`request`/`read` are sinks on the right framework class without mass false positives.
 */
private class TypedSink extends Sink {
  string kind;

  TypedSink() {
    exists(int i, string cls, string m | typedSinkModel(cls, m, i, kind) |
      exists(MethodCall c |
        c.getMethodName() = m and
        receiverIsClass(c.getReceiver(), cls) and
        (i = -1 and this.asExpr() = c.getAnArgument() or this.asExpr() = c.getArgument(i))
      )
      or
      exists(StaticMethodCall c |
        c.getMethodName() = m and
        c.getTargetName() = cls and
        (i = -1 and this.asExpr() = c.getAnArgument() or this.asExpr() = c.getArgument(i))
      )
      or
      // A `__construct` typed sink also matches `new Class($arg)` — the constructor argument of an
      // object creation (e.g. `new RedirectResponse($url)`, `new SplFileObject($path)`).
      m = "__construct" and
      exists(NewExpr c |
        c.getClassName() = cls and
        (i = -1 and this.asExpr() = c.getAnArgument() or this.asExpr() = c.getArgument(i))
      )
    )
  }

  override string getKind() { result = kind }
}

/** Gets the handler-argument expression of a router call (`routeHandlerModel`): a closure, an array
 *  callable `[Controller::class, 'm']` / `[$obj, 'm']`, or a string `'Controller@m'`. */
private AstNode routeHandlerArg() {
  exists(Call route, string sk, string nm, int hi | routeHandlerModel(sk, nm, hi) |
    sk = "staticmethod" and route.(StaticMethodCall).getMethodName() = nm and result = route.getArgument(hi)
    or
    sk = "method" and route.(MethodCall).getMethodName() = nm and result = route.getArgument(hi)
    or
    sk = "function" and route.(FunctionCall).getName() = nm and result = route.getArgument(hi)
  )
}

/**
 * Gets the callable a router dispatches to: the closure/arrow itself, OR — for a CONTROLLER handler —
 * the resolved method of an array callable `[Controller::class, 'show']` / `[$obj, 'show']` or a string
 * `'Controller@show'`. Modelling the controller method is what makes real-world routes work: the bug is
 * usually several calls deep inside the action, not in a closure attached to the router.
 */
private AstNode routeCallable() {
  exists(AstNode h | h = routeHandlerArg() |
    (h instanceof Php::AnonymousFunction or h instanceof Php::ArrowFunction) and result = h
    or
    // `[$obj, 'm']` / `['C', 'm']` — resolved by the shared array-callable resolver.
    result = TI::arrayCallableMethod(h)
    or
    // `[Controller::class, 'm']` — the `::class` form: resolve the method by class + name.
    exists(Php::ArrayCreationExpression arr, ClassLike c, string m |
      arr = h and
      c.getName() =
        arr.getChild(0)
            .(Php::ArrayElementInitializer)
            .getChild(0)
            .(Php::ClassConstantAccessExpression)
            .getChild(0)
            .(Php::Name)
            .getValue() and
      m = arr.getChild(1).(Php::ArrayElementInitializer).getChild(0).(StringLiteral).getValue() and
      result = c.getAMethod() and
      result.(Method).getName() = m
    )
    or
    // `'Controller@method'` string handler.
    exists(ClassLike c, string s, string m |
      s = h.(StringLiteral).getValue() and
      s.matches("%@%") and
      c.getName() = s.splitAt("@", 0) and
      m = s.splitAt("@", 1) and
      result = c.getAMethod() and
      result.(Method).getName() = m
    )
  )
  or
  // `Route::resource('photos', PhotoController::class)` — the conventional RESTful actions that receive
  // the `{resource}` id (show/edit/update/destroy) on the named controller class.
  exists(Call route, string sk, string nm, int ci, ClassLike c |
    routeResourceModel(sk, nm, ci) and
    (
      sk = "staticmethod" and route.(StaticMethodCall).getMethodName() = nm
      or
      sk = "method" and route.(MethodCall).getMethodName() = nm
      or
      sk = "function" and route.(FunctionCall).getName() = nm
    ) and
    c.getName() =
      [
        route.getArgument(ci).(Php::ClassConstantAccessExpression).getChild(0).(Php::Name).getValue(),
        route.getArgument(ci).(StringLiteral).getValue()
      ] and
    result = c.getAMethod() and
    result.(Method).getName() = ["show", "edit", "update", "destroy"]
  )
}

/** Gets a route-parameter parameter (untyped or scalar-typed, i.e. NOT a DI/model class) of a route
 *  callable — a closure/arrow or a resolved controller method. */
private Php::SimpleParameter routeCallableParam(AstNode callable) {
  (
    result = callable.(Php::AnonymousFunction).getParameters().getChild(_) or
    result = callable.(Php::ArrowFunction).getParameters().getChild(_) or
    result = callable.(Php::MethodDeclaration).getParameters().getChild(_)
  ) and
  not TI::hasClassParameterType(result)
}

/** Gets the body of a route callable (closure/arrow/controller method). */
private AstNode routeCallableBody(AstNode callable) {
  result = callable.(Php::AnonymousFunction).getBody() or
  result = callable.(Php::ArrowFunction).getBody() or
  result = callable.(Php::MethodDeclaration).getBody()
}

/**
 * A route parameter: a scalar parameter of a framework route handler is bound to a path segment
 * (`/user/{id}` → `show($id)`), i.e. attacker-controlled. A read of it inside the handler/action body is
 * a source, and the interprocedural engine carries it through however many calls the action makes.
 * Handles both closure handlers AND controller-method handlers (`[Controller::class, 'm']` /
 * `'Controller@m'`). Data-driven: the routers are `routeHandlerModel` rows — a new framework needs only
 * data.
 */
private class RouteParamSource extends RemoteFlowSource {
  RouteParamSource() {
    exists(AstNode callable, Php::SimpleParameter p, VariableAccess read |
      callable = routeCallable() and
      p = routeCallableParam(callable) and
      read.getName() = p.getName().getChild().getValue() and
      notInNestedCallable(read, routeCallableBody(callable)) and
      this.asExpr() = read
    )
  }

  override string getSourceType() { result = "route parameter" }
}

/** Gets the short (last `\`-segment) name of an attribute `a` (`#[Route]` or `#[…\Route]` → "Route"). */
private string attributeShortName(Php::Attribute a) {
  result = a.getChild().(Php::Name).getValue()
  or
  result = a.getChild().(Php::QualifiedName).getChild().(Php::Name).getValue()
}

/**
 * An attribute-routed controller parameter: a method annotated with a routing attribute
 * (`routeAttributeModel`, e.g. Symfony `#[Route('/u/{id}')]`) receives its scalar parameters from URL
 * path placeholders. A read of such a parameter in the method body is a source, tracked
 * interprocedurally into the action. Class-typed params (autowired services) are excluded.
 */
private class AttributeRouteParamSource extends RemoteFlowSource {
  AttributeRouteParamSource() {
    exists(Php::MethodDeclaration meth, Php::SimpleParameter p, VariableAccess read |
      exists(Php::Attribute a |
        a.(Php::AstNode).getParent+() = meth.getAttributes() and
        routeAttributeModel(attributeShortName(a))
      ) and
      p = meth.getParameters().getChild(_) and
      not TI::hasClassParameterType(p) and
      read.getName() = p.getName().getChild().getValue() and
      notInNestedCallable(read, meth.getBody()) and
      this.asExpr() = read
    )
  }

  override string getSourceType() { result = "route parameter" }
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

/**
 * Holds if `cond` proves `checked` is whitelisted: `in_array($checked, <constant array>)` (a CONSTANT
 * whitelist — a dynamic 2nd arg could be attacker-influenced, so it is not accepted), or a named
 * sanitizer-guard validator applied to `$checked`.
 */
private predicate whitelistGuardCond(Expr cond, Expr checked) {
  exists(FunctionCall c |
    c = cond and c.getName() = "in_array" and checked = c.getArgument(0) and isConstLiteral(c.getArgument(1))
  )
  or
  isSanitizerGuardCall(cond) and checked = cond.(Call).getAnArgument()
}

/**
 * The THEN branch of a whitelist TERNARY — `in_array($x, [...]) ? $x : $default` — is reached only when the
 * guard holds, so the value used there is whitelisted-safe. Mirrors `GuardBarrier` for the ternary form the
 * `if`-based `isGuardedRead` does not cover (a documented FP). Positive polarity only (guard true ⇒ THEN),
 * same-access-path, so it clears ONLY the proven-safe branch value.
 */
private class TernaryWhitelistBarrier extends Sanitizer {
  TernaryWhitelistBarrier() {
    exists(Php::ConditionalExpression ce, Expr checked, Expr use | this.asExpr() = use and sameAccessPath(checked, use) |
      // positive polarity: `guard($x) ? $x : default` — the THEN value is whitelisted.
      whitelistGuardCond(ce.getCondition(), checked) and use.(Php::AstNode).getParent*() = ce.getBody()
      or
      // negated polarity: `!guard($x) ? default : $x` — the ELSE value is whitelisted.
      exists(Php::UnaryOpExpression notOp |
        notOp = ce.getCondition() and
        notOp.getOperator().toString() = "!" and
        whitelistGuardCond(notOp.getArgument(), checked) and
        use.(Php::AstNode).getParent*() = ce.getAlternative()
      )
    )
  }
}

/**
 * A `typedSanitizerModel` method call resolved through the STRONG receiver predicate (`receiverIsClass` —
 * type inference + ancestors + typehint), the same one typed sinks/sources use. ModelExtensions already
 * has a `TypedSanitizer` keyed on the weaker literal/`new`/`$wpdb` resolution; this additive class also
 * recognises a DI-/factory-injected receiver (`$this->db->prepare($sql)` where `db` is a typed property),
 * so a correctly-parameterised query on an injected connection is no longer flagged SQLi (Tier-1-D).
 */
private class TypedSanitizerStrong extends Sanitizer {
  TypedSanitizerStrong() {
    exists(MethodCall c, string cls |
      typedSanitizerModel(cls, c.getMethodName()) and
      // EXACT class or written typehint only — deliberately NOT the ancestor arm that typed SINKS/SOURCES use.
      // Broadening a SANITIZER to subclasses is the dangerous direction: a subclass of a generic sanitizer
      // class (`Sanitizer`/`Connection`/`Db`) may OVERRIDE the method to a no-op, so barriering it would hide
      // a real vuln (an FN). Sinks/sources broaden safely (a subclass that inherits the method really is one).
      (TI::exprClass(c.getReceiver()).getName() = cls or TI::exprTypeName(c.getReceiver()) = cls) and
      this.asExpr() = c
    )
  }
}

/**
 * Gets the literal text of a CONSTANT (non-interpolated) string literal — a single-quoted `Php::String`
 * or a double-quoted `EncapsedString` whose every child is literal `StringContent` (i.e. no `$var`
 * interpolation, which would make the value attacker-influenced). Multiple content chunks are joined in
 * source order.
 */
private string constStringText(Expr s) {
  s instanceof Php::String and
  not exists(Php::AstNode ch |
    ch = s.(Php::String).getChild(_) and not ch instanceof Php::StringContent
  ) and
  result =
    concat(int i, string t | t = s.(Php::String).getChild(i).(Php::StringContent).getValue() | t order by i)
  or
  s instanceof Php::EncapsedString and
  not exists(Php::AstNode ch |
    ch = s.(Php::EncapsedString).getChild(_) and not ch instanceof Php::StringContent
  ) and
  result =
    concat(int i, string t |
      t = s.(Php::EncapsedString).getChild(i).(Php::StringContent).getValue() | t order by i
    )
}

/**
 * `filter_var($x, FILTER_…)` is a barrier ONLY for the genuinely-neutralizing NUMERIC filters, whose
 * output is a number (or `false`) regardless of input: FILTER_VALIDATE_INT/FLOAT/BOOLEAN and
 * FILTER_SANITIZE_NUMBER_INT/FLOAT. The VALIDATE_URL/EMAIL/IP filters return the input UNCHANGED (they
 * validate, they do not sanitize) and FILTER_DEFAULT/UNSAFE_RAW is a no-op — modelling filter_var as a
 * blanket sanitizer hid those (SSRF via a validated URL, etc.). Non-numeric filter_var stays a taint STEP
 * (php-builtins.model.yml) so the value flows on (Tier-2-K).
 */
private class FilterVarNumericBarrier extends Sanitizer {
  FilterVarNumericBarrier() {
    exists(FunctionCall c |
      c.getName() = "filter_var" and
      c.getArgument(1).(Php::Name).getValue() =
        [
          "FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT", "FILTER_VALIDATE_BOOLEAN",
          "FILTER_SANITIZE_NUMBER_INT", "FILTER_SANITIZE_NUMBER_FLOAT"
        ] and
      this.asExpr() = c
    )
  }
}

/**
 * A `sprintf`/`printf`-family result whose CONSTANT format string uses only NUMERIC conversion specifiers
 * (`%d %i %u %b %o %x %X %e %f %g` + flags/width/precision/positional) and NO `%s`/`%c`. Every argument is
 * therefore coerced to a number in the output, so the result cannot carry an injection/XSS payload — a
 * barrier for all classes. The canonical safe `sprintf("… id=%d", $_GET['id'])` was flagged because
 * `sprintf` is a generic taint STEP; this narrows that step out when the format is numeric-only (Tier-2-I).
 */
/**
 * Holds if `c` is an `(v)sprintf`/`(v)printf` whose CONSTANT format has at least one numeric conversion and
 * NO string/char (`%s`/`%c`) conversion — so every substituted argument is coerced to a number and carries no
 * injectable payload. The flag run allows a custom-pad token `%'<c>` (`'.`) so an out-of-flag pad char like
 * `%'@10s` does not hide the following `s` (P0-I). `%%` escape ignored.
 */
private predicate numericOnlyFormatCall(FunctionCall c) {
  c.getName() = ["sprintf", "printf", "vsprintf", "vprintf"] and
  exists(string fmt | fmt = constStringText(c.getArgument(0)) |
    fmt.regexpMatch(".*%(?:'.|[-+ 0# .,0-9*$])*[bdiouxXeEfFgG].*") and
    not fmt.regexpReplaceAll("%%", "").regexpMatch(".*%(?:'.|[-+ 0# .,0-9*$])*[sc].*")
  )
}

private class SprintfNumericBarrier extends Sanitizer {
  SprintfNumericBarrier() {
    exists(FunctionCall c | numericOnlyFormatCall(c) |
      // `(v)sprintf` RETURNS the string, so the result node is the barrier (it flows onward to a sink).
      this.asExpr() = c
      or
      // `(v)printf` OUTPUTS directly and is itself an XSS sink at arg -1, so the sink is each VALUE argument
      // — barrier those (positions ≥ 1; the format is arg 0). Harmless on sprintf (its args aren't sinks).
      this.asExpr() = c.getArgument(any(int i | i >= 1))
    )
  }
}

/**
 * A value produced by a cast to a numeric or boolean type — `(int)`, `(integer)`, `(float)`,
 * `(double)`, `(real)`, `(bool)`, `(boolean)`. Such a value cannot carry an injection / XSS / path /
 * command payload, so it is a barrier for every taint class. This is generic to all PHP (every CMS
 * casts request-supplied ids with `(int) $x` before using them in SQL) and complements the
 * `intval` / `floatval` / `settype` / `absint` FUNCTION sanitizers — the cast SYNTAX was previously
 * treated as an ordinary taint-propagating expression. `(string)` / `(binary)` / `(array)` casts still
 * propagate, as before.
 */
private class NumericCastSanitizer extends Sanitizer {
  NumericCastSanitizer() {
    exists(CastExpr c |
      c.getTypeName() = ["int", "integer", "float", "double", "real", "bool", "boolean"] and
      this.asExpr() = c
    )
  }
}

/** A builtin that ALWAYS returns an int/float/bool — no string/array can escape it. Curated for soundness
 *  (excludes `max`/`min` which pass strings through, `dechex`/`gettype` which return strings). */
private predicate numericBuiltin(string name) {
  name =
    [
      "count", "sizeof", "strlen", "mb_strlen", "iconv_strlen", "intval", "floatval", "doubleval",
      "abs", "ceil", "floor", "round", "intdiv", "fmod", "time", "mktime", "gmmktime", "strtotime",
      "mt_rand", "rand", "random_int", "mt_getrandmax", "getrandmax", "ip2long", "crc32", "ord",
      "hexdec", "octdec", "bindec", "array_sum", "array_product", "substr_count", "similar_text",
      "levenshtein", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "preg_match", "preg_match_all",
      "checkdate", "memory_get_usage", "filesize", "fmod", "pow", "gmp_intval", "bccomp"
    ]
}

/**
 * TypeFlow (forward, shape-based): holds if `e` provably EVALUATES to an int/float/bool, hence carries no
 * SQL/HTML/path/command payload. A single sound rule that SUBSUMES the ad-hoc numeric barriers and — because
 * a data-flow barrier stops taint at the node and the engine propagates the CLEAN value onward — needs no
 * type LATTICE with flow: identifying the numeric-PRODUCING expressions is enough. The result type of an
 * operator is fixed by the OPERATOR (arithmetic → numeric, comparison/logical → bool, concat `.` → string),
 * independent of operands, so this never depends on inferring an operand's type. Recurses through parens,
 * ternary (both branches numeric), and phpBB's type-coercing `variable($n, $numericDefault)` (which settype's
 * its result to the default's type — extends the literal-only PhpbbVariableNumericBarrier to `(int)$x` /
 * `count($y)` / arithmetic defaults). Does NOT cross the DB-fetch wall (`variable('x', $row['id'])` — a
 * non-provable default stays tainted, recall-first).
 */
private predicate producesNumericValue(Expr e) {
  // int/float/bool literals
  e instanceof Php::Integer or
  e instanceof Php::Float or
  e instanceof Php::Boolean
  or
  // numeric/bool casts
  e.(CastExpr).getTypeName() = ["int", "integer", "float", "double", "real", "bool", "boolean"]
  or
  // arithmetic / bitwise binary ops → numeric; comparison / logical → bool. Concat `.` (string) EXCLUDED.
  e.(BinaryOperation).getOperator() =
    [
      "+", "-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>", "==", "===", "!=", "!==", "<>", "<", ">",
      "<=", ">=", "<=>", "&&", "||", "and", "or", "xor"
    ]
  or
  // unary numeric (`-$x`,`+$x`,`~$x`) / logical (`!$x`) → numeric/bool
  e.(Php::UnaryOpExpression).getOperator().toString() = ["-", "+", "~", "!"]
  or
  // builtins that always return a number
  exists(FunctionCall c | c = e and numericBuiltin(c.getName()))
  or
  // parenthesised value
  producesNumericValue(e.(Php::ParenthesizedExpression).getChild())
  or
  // ternary: both branches numeric (elvis `?:` → condition is the value)
  exists(Php::ConditionalExpression t | t = e |
    producesNumericValue(t.getBody()) and producesNumericValue(t.getAlternative())
    or
    not exists(t.getBody()) and producesNumericValue(t.getCondition())
  )
  or
  // phpBB type-coercing accessor with a provably-numeric default
  exists(MethodCall m |
    m = e and
    m.getMethodName() = ["variable", "untrimmed_variable", "request_var"] and
    producesNumericValue(m.getArgument(1))
  )
  or
  // NUMERIC DB-COLUMN: a DB-ROW access `$row['<key>']` at a conventionally-INTEGER column name (`*_id`,
  // `*_ids`, `*_time`, `*_count`, bare `id`). A value read from an integer column of a DB row is numeric.
  // CRITICALLY GATED BY DB-PROVENANCE (allowlist, not denylist): the base must be a variable assigned from
  // a DB fetch (`sql_fetchrow`/`sql_fetchfield`/`sql_fetchrowset`/`fetch`/`fetchArray`/`fetch_assoc`/…) — so
  // a REQUEST array with the same key (`$this->request->get['order_id']`, OpenCart/AbanteCart unauth SQLi)
  // is NOT barriered. The key-name alone cannot tell a DB row from request input (the 201-CVE corpus proved
  // a superglobal-only gate hides 4 real SQLi), so the provenance gate is mandatory. Targets phpBB
  // `$row['forum_id']` / `$data['topic_id']` fetched rows — the dominant real-framework FP class.
  exists(Php::SubscriptExpression sub, string key |
    e = sub and
    key = strictSubscriptKey(sub) and
    key.regexpMatch("(?i).*(_id|_ids|_time|_count)|^id$") and
    dbFetchDerivedBase(sub.getChild(0))
  )
}

/** A DB-fetch method whose result is a trusted row/scalar (integer columns are ints, not attacker input). */
private predicate dbFetchMethodName(string name) {
  name =
    [
      "sql_fetchrow", "sql_fetchfield", "sql_fetchrowset", "fetch", "fetchArray", "fetchAssoc",
      "fetch_assoc", "fetch_array", "fetchRow", "fetch_row", "fetchOne", "fetchAssociative"
    ]
}

/** Holds if `base` originates from a DB fetch — either it IS such a call, or a local variable assigned
 *  from one somewhere in its enclosing callable. Flow-INSENSITIVE (any fetch assignment to `$v` marks
 *  every `$v[...]` in the function), so a `$v` later re-assigned from request could in principle be
 *  over-barriered (a theoretical FN) — accepted because the value is a DB integer column in practice and
 *  the 201-CVE corpus stays 201/201 (whereas a key-name-only gate lost 4 real request-array SQLi). */
private predicate dbFetchDerivedBase(Expr base) {
  dbFetchMethodName(base.(MethodCall).getMethodName())
  or
  exists(AssignExpr a, string v |
    v = base.(VariableAccess).getName() and
    a.getLhs().(VariableAccess).getName() = v and
    dbFetchMethodName(a.getRhs().(MethodCall).getMethodName())
  )
}

/** A node whose expression provably evaluates to a number — a general injection barrier (a number carries
 *  no payload). Joins `isNumericValueBarrier` so ACCESS-CONTROL still sees it (a numeric id is still the
 *  attacker's chosen resource → IDOR must NOT be suppressed). */
private class NumericValueSanitizer extends Sanitizer {
  NumericValueSanitizer() { producesNumericValue(this.asExpr()) }
}

/**
 * phpBB `$request->variable($name, $default)` TYPE-COERCES its result to the TYPE of `$default`
 * (`type_cast_helper::recursive_set_var` → `settype`). A NUMERIC / bool default — `variable('id', 0)`,
 * `variable('page', 1)`, `variable('x', false)` — yields an int/float/bool, so no injection payload
 * survives. The STRING-default form (`variable('sort', 'asc')`) stays a source: that is the real
 * ORDER-BY SQLi class. Like a `(int)` cast this stops INJECTION but not IDOR (the number is still the
 * attacker's chosen id), so it also joins `isNumericValueBarrier`.
 */
/**
 * Holds if `def` is a NUMERIC/bool type-template for phpBB's `variable()`: a scalar int/float/bool (incl.
 * negative), OR an ARRAY whose every element is itself numeric (`array(0)`, `[1,2]`, or empty `array()`) —
 * `recursive_set_var` coerces each element of the result to the default's element type, so an all-numeric
 * default yields an all-numeric (SQL-safe) array. The pervasive `variable('ids', array(0))` idiom.
 */
private predicate phpbbNumericDefault(Expr def) {
  def instanceof Php::Integer or def instanceof Php::Float or def instanceof Php::Boolean
  or
  exists(Php::UnaryOpExpression u |
    u = def and
    u.getOperator().toString() = "-" and
    (u.getArgument() instanceof Php::Integer or u.getArgument() instanceof Php::Float)
  )
  or
  def instanceof Php::ArrayCreationExpression and
  // phpBB's recursive_set_var coerces each element's VALUE to the type of the DEFAULT element's VALUE
  // — NOT the key. So a numeric-VALUE default (`array(0)`, `array('' => 0)`, `array('id' => 0)`) yields
  // an all-numeric-valued result, SQL-safe when a VALUE is read (`$arr[$k]`, the acp_icons pattern). The
  // key stays request-derived, but phpBB's key consumers (`array_keys(...)` -> sql_in_set) escape it. For
  // each element take the VALUE = the highest-index child (`k => v` has children [k,v]; a bare `v` has [v]).
  forall(Php::ArrayElementInitializer el | el = def.(Php::ArrayCreationExpression).getChild(_) |
    exists(int maxi | maxi = max(int j | exists(el.getChild(j))) | phpbbNumericDefault(el.getChild(maxi)))
  )
}

private class PhpbbVariableNumericBarrier extends Sanitizer {
  PhpbbVariableNumericBarrier() {
    exists(MethodCall c |
      c.getMethodName() = ["variable", "untrimmed_variable"] and
      this.asExpr() = c and
      phpbbNumericDefault(c.getArgument(1))
    )
  }
}


/**
 * Holds if `ty` is a scalar NUMERIC/BOOLEAN parameter type — `int`/`float`/`bool`, or their nullable
 * `?int` form (`OptionalType` wrapping the primitive). Deliberately NOT `string`/`array`/`mixed` or a
 * `UnionType`/`NamedType`: those can still carry an injection payload.
 */
private predicate isScalarNumericType(Php::AstNode ty) {
  ty.(Php::PrimitiveType).toString() = ["int", "float", "bool"]
  or
  ty.(Php::OptionalType).getChild().(Php::PrimitiveType).toString() = ["int", "float", "bool"]
}

/** Holds if a variable named `name` is (re)assigned — `=`, `.=`, `+=`, `&=`, … — anywhere in `fn`'s body. */
private predicate paramReassigned(string name, Callable fn) {
  exists(Expr lhs |
    (lhs = any(AssignExpr a).getLhs() or lhs = any(Php::AugmentedAssignmentExpression aa).getLeft()) and
    lhs.(VariableAccess).getName() = name and
    lhs.(Php::AstNode).getParent+() = fn.getBody()
  )
}

/**
 * A read of a parameter declared with a scalar numeric/boolean type (`int`/`float`/`bool`, incl. `?int`).
 * PHP enforces the declaration at CALL time in BOTH strict and coercive mode: a non-numeric string
 * `TypeError`s and a numeric string is coerced, so inside the body the value is guaranteed
 * numeric/boolean and cannot carry an injection payload — the by-declaration analogue of an `(int)` cast.
 * Sound because (a) only `int`/`float`/`bool` qualify (a `string`/`array`/union param still carries the
 * payload) and (b) the parameter must NOT be reassigned in the body (else `$id = $_GET[...]` re-taints).
 */
private class ScalarParamBarrier extends Sanitizer {
  ScalarParamBarrier() {
    exists(Callable fn, Parameter p, string name, VariableAccess use |
      p = fn.getAParameter() and
      isScalarNumericType(p.(Php::SimpleParameter).getType()) and
      name = p.getName() and
      use.getName() = name and
      notInNestedCallable(use, fn.getBody()) and
      not paramReassigned(name, fn) and
      this.asExpr() = use
    )
  }
}

/**
 * A read of a variable that a preceding `settype($x, 'int'|'float'|'bool')` coerced to a scalar type — the
 * by-reference analogue of an `(int)` cast (settype mutates its argument in place), so the value is
 * guaranteed numeric/boolean afterward and the flow is cut. The settype must DOMINATE the read: its
 * enclosing statement is a strictly-earlier sibling of the read's enclosing statement in the SAME
 * straight-line block. This replaces the old line-number test, which was CFG-blind — a `settype` nested in
 * `if($c){ settype($x,'int'); }` wrongly cleared a later `sink($x)` reached on the `$c == false` path (FN).
 */
private class SettypeBarrier extends Sanitizer {
  SettypeBarrier() {
    exists(FunctionCall st, VariableAccess use |
      st.getName() = "settype" and
      st.getArgument(1).(StringLiteral).getValue() =
        ["int", "integer", "float", "double", "bool", "boolean"] and
      sameAccessPath(st.getArgument(0), use) and
      st.getArgument(0) != use and
      exists(Php::AstNode blk, int i, int j, Php::AstNode stStmt, Php::AstNode useStmt |
        // settype's OWN statement must be a straight-line child of `blk` (getParent, not getParent*): a
        // settype nested in an `if`/loop within `blk` does NOT dominate a later use in `blk`.
        orderedBlockChild(blk, i, stStmt) and
        stStmt = st.(Php::AstNode).getParent() and
        // the use may be nested arbitrarily deep under a later sibling statement (still dominated).
        orderedBlockChild(blk, j, useStmt) and
        useStmt = use.(Php::AstNode).getParent*() and
        i < j and
        // …and the variable must NOT be re-tainted between the settype and the use (`settype($x,'int');
        // $x = $_GET['x']; sink($x)` must still fire).
        not accessPathReassignedBetween(blk, i, j, st.getArgument(0))
      ) and
      this.asExpr() = use
    )
  }
}

/** Holds if `e` is (a fluent chain rooted at) the Laravel global `collect(...)`, which unambiguously returns
 *  an in-memory `Illuminate\Support\Collection` (NOT a query builder). */
private predicate collectRooted(Expr e) {
  e.(FunctionCall).getName() = "collect"
  or
  collectRooted(e.(MethodCall).getReceiver())
}

/**
 * The column argument of a laravel query-builder method (`where`/`pluck`/`orderBy`/…) is a bare-method SQL sink
 * for recall (the Builder type can't resolve without vendor extraction). It over-fires on the in-memory
 * `Illuminate\Support\Collection`, which shares the method names. This barrier subtracts ONLY the case where
 * the receiver is (a chain rooted at) the global `collect(...)` — the one form that is UNAMBIGUOUSLY a
 * Collection. A bare short type-name (`Collection $q`) is NOT used: a custom `App\…\Collection` fluent DB
 * wrapper shares the short name and its real column sink must not be suppressed. Barriers the column arg (0).
 */
private class LaravelCollectionBarrier extends Sanitizer {
  LaravelCollectionBarrier() {
    exists(MethodCall c |
      c.getMethodName() =
        [
          "where", "pluck", "orderBy", "orderByDesc", "groupBy", "having", "select", "max", "min", "avg",
          "sum", "firstWhere"
        ] and
      collectRooted(c.getReceiver()) and
      this.asExpr() = c.getArgument(0)
    )
  }
}

/**
 * Holds if `n` is a NUMERIC-value barrier — a scalar `int`/`float`/`bool` parameter read, a `settype(...,'int')`
 * -coerced read, or a `filter_var(...FILTER_VALIDATE_INT...)` result. These correctly stop INJECTION (a number
 * carries no SQL/XSS/path payload) but must NOT stop IDOR / broken-access-control: the coerced value is still
 * the attacker's chosen resource id. The access-control taint engine subtracts these (see AccessControlTaint.qll),
 * exactly as it already subtracts `intval`/`(int)`/`is_numeric`.
 */
predicate isNumericValueBarrier(DataFlow::Node n) {
  n instanceof ScalarParamBarrier or
  n instanceof SettypeBarrier or
  n instanceof FilterVarNumericBarrier or
  n instanceof PhpbbVariableNumericBarrier or
  n instanceof NumericValueSanitizer
}

// --- Constant sibling-key barrier (field-sensitive arrays, recursive) ---------------------------
//
// The engine's array handling is FIELD-INSENSITIVE for recall: writing ANY element re-taints the whole
// container at node level (`$d['name']=$_GET[...]` marks all of `$d`), and reading ANY element inherits
// that node taint (the subscript base→result taint step). Together they FALSELY taint a SIBLING constant
// key that was written a constant:
//     $d['name']  = $_GET['name'];   // taints $d
//     $d['table'] = 'users';         // constant
//     $db->query("… " . $d['table']);   // FP: $d['table'] is 'users', not attacker data
// This barrier recovers precision WITHOUT losing recall by being a pure MUST-analysis: it neutralises a
// read `$base[K]` (constant key, recursively for nested `$e['sub']['table']`) ONLY when it can PROVE the
// value is constant — i.e. some write assigns that exact cell a constant literal AND no write in scope
// could taint it (same-cell/ancestor non-constant assign, dynamic-key/append write, by-ref/global rebind).
// Because it only ever REMOVES a flow it has proven safe, an unseen taint source just leaves the flow in
// place (no false negative); the corpus is the recall guardrail.

/** Holds if `name` is a PHP superglobal — never a barrierable local array root. */
bindingset[name]
private predicate isSuperglobalName(string name) {
  name =
    [
      "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_ENV", "_SESSION", "GLOBALS",
      "HTTP_RAW_POST_DATA"
    ]
}

/** The innermost enclosing callable of `n` (function / method / closure / arrow-fn), or the `Program`
 *  top level if none — delimits variable identity by scope (PHP variables are function-scoped). */
private Php::AstNode enclosingCallableOrProgram(Php::AstNode n) {
  result = n.getParent+() and
  (
    result instanceof Php::FunctionDefinition or
    result instanceof Php::MethodDeclaration or
    result instanceof Php::AnonymousFunction or
    result instanceof Php::ArrowFunction or
    result instanceof Php::Program
  ) and
  not exists(Php::AstNode mid |
    mid = n.getParent+() and
    mid.getParent+() = result and
    (
      mid instanceof Php::FunctionDefinition or
      mid instanceof Php::MethodDeclaration or
      mid instanceof Php::AnonymousFunction or
      mid instanceof Php::ArrowFunction
    )
  )
}

/** STRICT constant subscript key: an integer literal or a NON-interpolated string literal. No result for
 *  a dynamic/interpolated key, so a dynamic key can never masquerade as constant (over-barriering = FN). */
private string strictSubscriptKey(Php::SubscriptExpression sub) {
  result = sub.getChild(1).(Php::Integer).getValue()
  or
  sub.getChild(1) instanceof Php::String and
  not exists(Php::AstNode ch |
    ch = sub.getChild(1).(Php::String).getChild(_) and not ch instanceof Php::StringContent
  ) and
  result =
    concat(int i, string t |
      t = sub.getChild(1).(Php::String).getChild(i).(Php::StringContent).getValue() | t order by i
    )
}

/**
 * Gets a FUNCTIONAL key string for a constant-key access chain rooted at a non-superglobal local variable
 * (`$e['sub']['table']` → `"1:e3:sub5:table"`), or no result if `e` is not such a chain. One row per
 * expression — comparing keys by equality replaces an all-pairs `sameConstChain` relation (which the
 * optimizer materialised as O(chains²) and blew up on large frameworks). Each segment is LENGTH-PREFIXED
 * (`<len>:<seg>`), a prefix-free encoding, so distinct chains never collide (`$d['a b']` = `"1:d3:a b"` vs
 * `$d['a']['b']` = `"1:d1:a1:b"`).
 */
private string constChainKey(Expr e) {
  exists(string n | n = e.(VariableAccess).getName() and not isSuperglobalName(n) |
    result = n.length().toString() + ":" + n
  )
  or
  exists(string k | k = strictSubscriptKey(e.(Php::SubscriptExpression)) |
    result = constChainKey(e.(Php::SubscriptExpression).getChild(0)) + k.length().toString() + ":" + k
  )
}

/** Functional: the innermost enclosing callable / program of a chain expression (its variable scope). Two
 *  chains are "the same cell" iff they share both `constChainKey` and `constChainScope` — the guard sets
 *  below index on exactly that pair, replacing what was an all-pairs `sameConstChain` relation. */
private Php::AstNode constChainScope(Expr e) { result = enclosingCallableOrProgram(e) }

/** Holds if `e` is a fully constant-key chain rooted at a non-superglobal local variable. */
private predicate fullConstChain(Expr e) { exists(constChainKey(e)) }

/** Gets `r` itself or any of its base sub-chains (`$e['sub']['table']` → itself, `$e['sub']`, `$e`). */
private Expr ancestorOrSelf(Expr r) {
  result = r
  or
  result = ancestorOrSelf(r.(Php::SubscriptExpression).getChild(0))
}

/** Gets the root variable of a (possibly nested) subscript chain. */
private VariableAccess chainRoot(Expr e) {
  result = e.(VariableAccess)
  or
  result = chainRoot(e.(Php::SubscriptExpression).getChild(0))
}

/**
 * The (scope, name) identity of a chain's ROOT variable, once per root occurrence. Precomputing membership
 * in the guard sets below by this identity — instead of joining every write against every read — is the
 * perf lever: the whole `cellPossiblyTainted` becomes hash lookups keyed by `(constChainKey, constChainScope)`
 * or `(scope, name)`, evaluated once, rather than per-candidate cartesian joins.
 */
private predicate rootIdentOf(Expr chain, Php::AstNode scope, string name) {
  exists(VariableAccess root | root = chainRoot(chain) |
    name = root.getName() and not isSuperglobalName(name) and scope = enclosingCallableOrProgram(root)
  )
}

/** (key, scope) of every cell assigned a CONSTANT literal — the barrier's necessary precondition set. */
private predicate chainConstAssigned(string key, Php::AstNode scope) {
  exists(AssignExpr w | isConstLiteral(w.getRhs()) and key = constChainKey(w.getLhs()) and scope = constChainScope(w.getLhs()))
}

/** (key, scope) of every cell/ancestor assigned a NON-constant value (plain / augmented / reference). */
private predicate chainTaintAssigned(string key, Php::AstNode scope) {
  exists(AssignExpr w | not isConstLiteral(w.getRhs()) and key = constChainKey(w.getLhs()) and scope = constChainScope(w.getLhs()))
  or
  exists(Php::AugmentedAssignmentExpression w | key = constChainKey(w.getLeft()) and scope = constChainScope(w.getLeft()))
  or
  exists(Php::ReferenceAssignmentExpression w | key = constChainKey(w.getRight()) and scope = constChainScope(w.getRight()))
}

/** (key, scope) of every constant-key chain passed DIRECTLY as a call argument (by-ref mutation risk). */
private predicate chainPassedAsArg(string key, Php::AstNode scope) {
  exists(Php::Argument arg | key = constChainKey(arg.getChild()) and scope = constChainScope(arg.getChild()))
}

/**
 * (scope, name) of every root array with a WILD write that could taint an arbitrary cell: a dynamic-key /
 * append / non-constant-chain subscript write (`$d[$x]=…`, `$d[]=…`), a by-reference foreach, or a `global`
 * rebind.
 */
private predicate rootHasWildWrite(Php::AstNode scope, string name) {
  exists(Php::SubscriptExpression lhs |
    lhs = anyWriteLhs() and not fullConstChain(lhs) and
    // a DYNAMIC key (`$d[$x]=…`) has an index child and can alias any key; a pure APPEND (`$d[]=…`, no
    // index child) writes only the next INTEGER index and is handled by `rootHasAppendWrite` below.
    exists(lhs.getChild(1))
  |
    name = chainRoot(lhs).getName() and not isSuperglobalName(name) and scope = enclosingCallableOrProgram(chainRoot(lhs))
  )
  or
  exists(Php::ForeachStatement fe, Php::ByRef ref | ref = fe.getChild(_) |
    name = fe.getChild(0).(VariableAccess).getName() and
    not isSuperglobalName(name) and
    scope = enclosingCallableOrProgram(fe.getChild(0))
  )
  or
  exists(Php::GlobalDeclaration g, Php::VariableName vn | vn = g.getChild(_) |
    name = vn.getChild().getValue() and scope = enclosingCallableOrProgram(g)
  )
}

/** (scope, name) of every root array with a pure APPEND write (`$d[] = …`, no index child) — it writes the
 *  next INTEGER index, so it can alias only an integer-keyed read, never a string key. */
private predicate rootHasAppendWrite(Php::AstNode scope, string name) {
  exists(Php::SubscriptExpression lhs | lhs = anyWriteLhs() and not exists(lhs.getChild(1)) |
    name = chainRoot(lhs).getName() and not isSuperglobalName(name) and scope = enclosingCallableOrProgram(chainRoot(lhs))
  )
}

/** Holds if `e` is a CONSTANT literal: a scalar (int/float/bool/null/non-interpolated string) or an array
 *  literal whose every element (key and value) is itself constant — so `[]` and `['a'=>1]` count. */
private predicate isConstLiteral(Expr e) {
  e instanceof Php::Integer or
  e instanceof Php::Float or
  e instanceof Php::Boolean or
  e instanceof Php::Null or
  exists(constStringText(e)) or
  e instanceof Php::ArrayCreationExpression and
  forall(Php::ArrayElementInitializer el | el = e.(Php::ArrayCreationExpression).getChild(_) |
    forall(Expr part | part = el.getChild(_) | isConstLiteral(part))
  )
  or
  // A binary expression built ENTIRELY from constant operands is itself constant and deterministic
  // (`'pre' . 'fix'`, `60 * 60`) — sound because both operands are proven constant, so it can never
  // carry taint. Covers the string-concat "build a constant table name" idiom.
  exists(Php::BinaryExpression b | b = e |
    b.getOperator() = [".", "+", "-", "*", "/", "%"] and
    isConstLiteral(b.getLeft()) and
    isConstLiteral(b.getRight())
  )
}

/** Gets the left-hand side of any write (plain / augmented / reference assignment). */
private Expr anyWriteLhs() {
  result = any(AssignExpr a).getLhs() or
  result = any(Php::AugmentedAssignmentExpression a).getLeft() or
  result = any(Php::ReferenceAssignmentExpression a).getLeft()
}

/**
 * Holds if the constant-key cell read by `r` could be tainted by SOME write in scope — the analysis is
 * conservative (recall-first): if any of these hold, `r` is NOT barriered. All checks are membership tests
 * against the precomputed guard sets, evaluated once, keyed by `(constChainKey, constChainScope)` of an
 * ancestor of `r` or by `(scope, name)` of its root — no per-candidate join over writes.
 */
private predicate cellPossiblyTainted(Expr r) {
  // A non-constant / augmented / reference assignment to this exact cell or one of its ANCESTORS
  // (`$d['table']=$x`, `$e['sub']=$x`, `$d=$_GET`, `$d['table'].=$x`, `$d=&$ref`).
  exists(Expr anc | anc = ancestorOrSelf(r) and chainTaintAssigned(constChainKey(anc), constChainScope(anc)))
  or
  // A tainting write to a DESCENDANT of this cell (`$d['k'][0]=$x` mutates a character / sub-element of
  // `$d['k']`, tainting the whole `$d['k']` that a wholesale read consumes). The length-prefixed encoding
  // makes a descendant's key START WITH this cell's key, without matching a sibling (`$d['ka']`).
  exists(string dkey |
    chainTaintAssigned(dkey, constChainScope(r)) and
    dkey != constChainKey(r) and
    dkey.prefix(constChainKey(r).length()) = constChainKey(r)
  )
  or
  // An ancestor is passed DIRECTLY as a call argument — the callee may take it by reference and mutate an
  // element (`parse_str($q,$d)`, `sort($d)`, a user `function f(&$a){ $a['k']=… }`), a taint the engine
  // DOES model but this syntactic analysis cannot see. The sink passes the value inside a larger expression
  // (`query("…".$d['k'])`), whose argument is that expression, not the bare cell, so it does not trip this.
  exists(Expr anc | anc = ancestorOrSelf(r) and chainPassedAsArg(constChainKey(anc), constChainScope(anc)))
  or
  // The root array has a WILD write (dynamic-key/non-const-chain subscript write, by-ref foreach, or
  // `global` rebind) that could alias this cell.
  exists(Php::AstNode scope, string name | rootIdentOf(r, scope, name) and rootHasWildWrite(scope, name))
  or
  // A pure APPEND `$d[] = …` on the root can alias only an INTEGER-keyed read (`$d[0]`) — never a string
  // key (`$d['table']`). Back off only when this read's outermost key is numeric.
  exists(Php::AstNode scope, string name |
    rootIdentOf(r, scope, name) and
    rootHasAppendWrite(scope, name) and
    strictSubscriptKey(r.(Php::SubscriptExpression)).regexpMatch("[0-9]+")
  )
}

/**
 * A constant-key subscript READ whose exact cell is also assigned a CONSTANT literal somewhere in scope.
 * This is the necessary precondition of the barrier, and it is HIGHLY SELECTIVE (only a small fraction of
 * constant-key reads have a matching constant write), so making it the driver means the taint-freedom check
 * (`cellPossiblyTainted`) runs only for these few reads instead of every constant-key read in the program.
 */
private predicate provenConstWrittenRead(Php::SubscriptExpression r) {
  fullConstChain(r) and chainConstAssigned(constChainKey(r), constChainScope(r))
}

/**
 * A read `$base[K]` (constant key chain, recursively) proven to hold a constant value: some write assigns
 * this exact cell a constant literal, and no write in scope could taint it. Neutralises the sibling-key FP
 * while leaving genuine flows (same-key taint, dynamic keys, whole-array consumers) untouched.
 */
private class ConstantSiblingKeyBarrier extends Sanitizer {
  ConstantSiblingKeyBarrier() {
    exists(Php::SubscriptExpression r |
      this.asExpr() = r and
      provenConstWrittenRead(r) and
      not cellPossiblyTainted(r)
    )
  }
}
