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
predicate isSanitizerGuardFunction(string name) { sanitizerGuardModel(name) }

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
  // Method sanitizers (`$pdo->quote()`, `$db->escape()`, …) are DATA — `sanitizerModel` method rows.
  // A `(int)`/`(float)`/`(bool)` cast is a language construct (not a call), so it stays structural here.
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
    c.getMethodName() =
      ["path", "get", "put", "putFile", "putFileAs", "download", "delete", "readStream", "prepend", "append"] and
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
    c.getMethodName() = ["loadXML", "loadHTML", "load"] and
    unsafeLibxmlFlag(c.getAnArgument()) and
    n.asExpr() = c.getArgument(0) and
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
}

/**
 * A class-qualified method source (`typedSourceModel`): `$request->get()` is a source only when the
 * receiver's inferred class matches, so `$someOtherObject->get()` is not. Re-arms the framework request
 * accessors that a bare method name could not model without false positives.
 */
private class TypedRemoteSource extends RemoteFlowSource {
  string sourceType;

  TypedRemoteSource() {
    exists(MethodCall c, string cls, string m |
      typedSourceModel(cls, m, sourceType) and
      c.getMethodName() = m and
      // resolve the receiver class by inference (declared classes) OR by its written type name (so
      // framework classes in an un-extracted vendor/ — `function (Request $r)` — still match).
      (TI::exprClass(c.getReceiver()).getName() = cls or TI::exprTypeName(c.getReceiver()) = cls) and
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
private class SymfonyBagSource extends RemoteFlowSource {
  SymfonyBagSource() {
    exists(Php::MemberCallExpression get, Php::MemberAccessExpression bag |
      get.getObject() = bag and
      bag.getName().(Php::Name).getValue() =
        ["query", "request", "attributes", "cookies", "files"] and
      (
        TI::exprClass(bag.getObject()).getName() = "Request" or
        TI::exprTypeName(bag.getObject()) = "Request"
      ) and
      get.getName().(Php::Name).getValue() =
        ["get", "all", "getInt", "getBoolean", "getAlpha", "getAlnum", "getDigits", "getString", "filter"] and
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
 * Dolibarr `GETPOST(name, type, …)` request accessor. The 2nd arg selects a sanitiser: `'int'`, `'alpha'`,
 * `'aZ09'`, … neutralise the value, so those calls are NOT sources; only the clearly-raw forms are — no
 * type arg, or the explicit `'none'` type. (`GETPOSTINT` is always-int and never matches.) This mirrors
 * the getenv split: model the accessor as a source only where it actually returns unsanitised input.
 */
private class GetpostSource extends RemoteFlowSource {
  GetpostSource() {
    exists(FunctionCall c | c.getName() = "GETPOST" and this.asExpr() = c |
      not exists(c.getArgument(1))
      or
      constantStringValue(c.getArgument(1)) = "none"
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
      prop.getName().(Php::Name).getValue() = ["get", "post", "cookie", "request"] and
      req = prop.getObject() and
      req.getName().(Php::Name).getValue() = "request" and
      this.asExpr() = sub
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
        (TI::exprClass(c.getReceiver()).getName() = cls or TI::exprTypeName(c.getReceiver()) = cls) and
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
      read.(Php::AstNode).getParent+() = routeCallableBody(callable) and
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
      read.(Php::AstNode).getParent+() = meth.getBody() and
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
