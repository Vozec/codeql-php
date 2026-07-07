/**
 * Data-driven (Models-as-Data) extension of the PHP security model.
 *
 * Sources, sinks, taint steps and sanitizers can be declared as *data* in `.model.yml` extension
 * files — no QL required. Each `extensible predicate` below is populated by those files, and the
 * classes here turn each row into a `RemoteFlowSource` / `Sink` / `AdditionalTaintStep` / `Sanitizer`.
 *
 * `subjectKind` is one of `"function"`, `"method"`, `"staticmethod"`. `argIndex`/`fromArg` use -1
 * to mean "any argument"; `toArg` uses -1 to mean "the return value".
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.DataFlow
private import codeql.php.Concepts
private import codeql.php.dataflow.internal.SsaImpl as SsaImpl
private import codeql.php.dataflow.internal.TypeInference as TI

/** A function/method whose result is a remote source of `sourceType`. */
extensible predicate sourceModel(string subjectKind, string name, string sourceType);

/**
 * A method that is a remote source ONLY when called on a receiver whose inferred class is `className`
 * (e.g. `Request::get`/`Request::input`), so a bare `$obj->get()` on an unrelated class is NOT a
 * source. The precise form of a `sourceModel` method row — avoids the false positives that forced the
 * bare method-name request sources to be dropped.
 */
extensible predicate typedSourceModel(string className, string methodName, string sourceType);

/** An argument (`argIndex`) of a function/method that is a `vulnKind` sink. */
extensible predicate sinkModel(string subjectKind, string name, int argIndex, string vulnKind);

/**
 * An argument (`argIndex`, -1 = any) of a method/static call `className::methodName` that is a
 * `vulnKind` sink ONLY when the receiver's inferred class (or the static scope) is `className`. The
 * precise form of `sinkModel` — lets generic method names (`get`/`query`/`execute`/`request`) be sinks
 * on the right framework class without flooding false positives on unrelated objects.
 */
extensible predicate typedSinkModel(string className, string methodName, int argIndex, string vulnKind);

/** Taint flows from argument `fromArg` to `toArg` (-1 = return) of a function/method. */
extensible predicate stepModel(string subjectKind, string name, int fromArg, int toArg);

/** A function/method whose result is sanitized. */
extensible predicate sanitizerModel(string subjectKind, string name);

/**
 * A validator function used as a branch GUARD: `if (g($x)) { … }` establishes that `$x` is safe on the
 * controlled branch (its result is a boolean, not a sanitized value). The NAMES are data here; the
 * barrier STRUCTURE (`isGuardedRead`) stays in QL.
 */
extensible predicate sanitizerGuardModel(string name);

/**
 * A higher-order built-in that invokes a callback: `name` calls the callable at argument
 * `callbackArg`, passing the value(s) from `dataArg` onward. Drives (a) data→callback-parameter taint,
 * (b) the string-callee sink dispatch (`array_map('system', $x)`), and (c) the tainted-callback sink
 * (`usort($a, $_GET['f'])`) — one data table instead of three hardcoded QL lists.
 */
extensible predicate callbackModel(string name, int callbackArg, int dataArg);

/**
 * A function that writes tainted data into a BY-REFERENCE output argument: `name` copies taint from
 * `fromArg` into the variable passed by reference at `toRefArg` (`parse_str($tainted, $out)` fills
 * `$out`). Later reads of that variable in the same scope are tainted.
 */
extensible predicate outRefModel(string name, int fromArg, int toRefArg);

/**
 * A method that sanitizes ONLY when called on a receiver of class `className` (e.g. `wpdb::prepare`
 * is safe, but a user's custom `MyClass::prepare` is not). Avoids the false-negatives of matching a
 * sanitizer purely by method name. Receiver type is resolved via SSA (`$o = new C()`) or, for the
 * common framework globals, by convention (`global $wpdb`).
 */
extensible predicate typedSanitizerModel(string className, string methodName);

/**
 * A framework router that dispatches a user request to a handler CALLABLE: a call to `name`
 * (subjectKind `function`/`method`/`staticmethod`) whose argument at `handlerArgIndex` is the request
 * handler (e.g. `Route::get('/u/{id}', function ($id) { … })` → `["staticmethod","get",1]`). The
 * handler closure's untyped scalar parameters are route parameters = attacker-controlled, so they
 * become sources. GENERIC mechanism: every framework's routers are just data rows, no engine change.
 */
extensible predicate routeHandlerModel(string subjectKind, string name, int handlerArgIndex);

/**
 * A routing ATTRIBUTE (`attributeName`, e.g. `Route`) — a controller method annotated with it (Symfony
 * `#[Route('/u/{id}')] public function show(int $id)`) receives its scalar parameters from URL path
 * placeholders = attacker-controlled. Those params become sources. Generic: a new framework's routing
 * attribute is just a data row. Matched by the attribute's short (last `\`-segment) name.
 */
extensible predicate routeAttributeModel(string attributeName);

/**
 * A RESTful resource router (`resource`/`apiResource`) whose argument at `controllerArgIndex` is a
 * controller class (`Route::resource('photos', PhotoController::class)`). The controller's conventional
 * resource actions that receive the `{resource}` id — `show`/`edit`/`update`/`destroy` — have that id as
 * a scalar parameter = attacker-controlled, so those params become sources. Generic: the resource
 * routers are data rows.
 */
extensible predicate routeResourceModel(string subjectKind, string name, int controllerArgIndex);

// ---- Audit MAD: declarative STRUCTURAL rules (a shape exists), separate from the taint MAD above.
//      A generic engine (SemgrepAudit.ql) reads these; adding an audit rule is a data row, never QL.

/**
 * F1 — a call to `name` (subjectKind `function`/`method`) exists. `guard` is a small fixed vocabulary
 * of extra conditions (`""`, or `"not-comparison"` = the call is not an operand of `==`/`===`).
 */
extensible predicate auditPresence(string subjectKind, string name, string guard, string ruleId);

/**
 * F2/F4 — the `argIndex`-th argument of a call to `name` satisfies `op operand`. `op` is a fixed
 * vocabulary: `equals` / `prefix` / `contains` (against the normalised string value), `nonliteral`
 * (not a plain string literal), `isvar` (a variable), `absent` (no such argument).
 */
extensible predicate auditArg(
  string subjectKind, string name, int argIndex, string op, string operand, string ruleId
);

/**
 * F3 — an array element `key => value` where the key satisfies `keyOp keyPat` and the value
 * `valOp valPat`. `context` is a fixed vocabulary constraining the enclosing construct: `""` (any),
 * `"new-response"` (inside a `new *Response(...)`), `"framework-ext"` (not inside a
 * prependExtensionConfig/loadFromExtension for a non-`framework` extension).
 */
extensible predicate auditArrayKV(
  string keyOp, string keyPat, string valOp, string valPat, string context, string ruleId
);

/**
 * F5 — flags the `flagKey => *` element of an array when a SIBLING `sibKey => *` in the same array
 * satisfies `sibValOp sibVal`, OR the sibling key is absent. `sibValOp` adds a `falsy` value op (a `false`
 * / `null` literal, or `env(_, false|null)`). For config-security audits that flag one key based on a
 * neighbouring flag — e.g. flag a session `'cookie'` when its `'http_only'` is false or missing.
 */
extensible predicate auditArraySibling(
  string flagKey, string sibKey, string sibValOp, string sibVal, string ruleId
);

/** Gets the class name of the receiver `recv`, resolved via `new C()` (SSA) or a known global. */
private string receiverClassName(VariableAccess recv) {
  // `$o = new C(); ... $o->m()`
  exists(
    VariableAccess w, AssignExpr a, Php::ObjectCreationExpression nw, SsaImpl::LocalVariable v,
    SsaImpl::Definition def, SsaImpl::Cfg::BasicBlock bbw, int iw, SsaImpl::Cfg::BasicBlock bbr,
    int ir
  |
    SsaImpl::variableAccessAt(bbr, ir, recv) and
    SsaImpl::Impl::ssaDefReachesRead(v, def, bbr, ir) and
    def.definesAt(v, bbw, iw) and
    SsaImpl::variableAccessAt(bbw, iw, w) and
    a.getLhs() = w and
    a.getRhs() = nw and
    result = nw.(NewExpr).getClassName()
  )
  or
  // Framework globals declared `global $wpdb;` map to their well-known class.
  recv.getName() = "wpdb" and result = "wpdb"
}

/** Gets the class whose method body (transitively) encloses `n` — the type of `$this` inside it. */
private ClassLike enclosingClassOf(AstNode n) {
  exists(Method m |
    n.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody() and
    result = m.getDeclaringType()
  )
}

/**
 * Resolves the class of a `$this->prop` receiver from a `$this->prop = <typed value>` assignment in the
 * SAME class. Covers the extremely common idiom of caching a framework object in a property —
 * `$this->db = $wpdb; … $this->db->prepare(…)` — so a class-scoped sanitizer/sink still applies. Without
 * this, a whole DB-manager class of parameterised `$this->db->prepare()` queries reads as unsanitised.
 */
private string propertyReceiverClassName(Php::MemberAccessExpression prop) {
  exists(string f, ClassLike cls, AssignExpr a, Php::MemberAccessExpression w |
    prop.getObject().(Php::VariableName).getChild().getValue() = "this" and
    prop.getName().(Php::Name).getValue() = f and
    enclosingClassOf(prop) = cls and
    a.getLhs() = w and
    w.getObject().(Php::VariableName).getChild().getValue() = "this" and
    w.getName().(Php::Name).getValue() = f and
    enclosingClassOf(w) = cls
  |
    a.getRhs().(VariableAccess).getName() = "wpdb" and result = "wpdb"
    or
    result = a.getRhs().(NewExpr).getClassName()
  )
}

private class TypedSanitizer extends Sanitizer {
  TypedSanitizer() {
    exists(MethodCall c, string cls |
      typedSanitizerModel(cls, c.getMethodName()) and
      (
        receiverClassName(c.getReceiver()) = cls or
        TI::exprTypeName(c.getReceiver()) = cls or
        propertyReceiverClassName(c.getReceiver()) = cls
      ) and
      this.asExpr() = c
    )
  }
}

/** Gets the `i`th argument of call `c`, any argument when `i = -1`, or the RECEIVER when `i = -2`
 *  (`$coll->map(...)` — the taint of a fluent method is in the receiver `$this`, not an argument). */
private Expr argOf(Call c, int i) {
  i >= 0 and result = c.getArgument(i)
  or
  i = -1 and result = c.getAnArgument()
  or
  i = -2 and result = c.(MethodCall).getReceiver()
}

/** Holds if call `c` names `name` and has the given `subjectKind`. */
private predicate callMatches(Call c, string subjectKind, string name) {
  subjectKind = "function" and name = c.(FunctionCall).getName()
  or
  subjectKind = "method" and name = c.(MethodCall).getMethodName()
  or
  subjectKind = "staticmethod" and name = c.(StaticMethodCall).getMethodName()
}

private class DataRemoteSource extends RemoteFlowSource {
  string sourceType;

  DataRemoteSource() {
    exists(Call c, string sk, string nm |
      sourceModel(sk, nm, sourceType) and callMatches(c, sk, nm) and this.asExpr() = c
    )
  }

  override string getSourceType() { result = sourceType }
}

private class DataSink extends Sink {
  string vulnKind;

  DataSink() {
    exists(Call c, string sk, string nm, int i |
      sinkModel(sk, nm, i, vulnKind) and callMatches(c, sk, nm) and this.asExpr() = argOf(c, i)
    )
  }

  override string getKind() { result = vulnKind }
}

private class DataStep extends AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Call c, string sk, string nm, int fromArg, int toArg |
      stepModel(sk, nm, fromArg, toArg) and callMatches(c, sk, nm)
    |
      pred.asExpr() = argOf(c, fromArg) and
      (
        toArg = -1 and succ.asExpr() = c
        or
        toArg >= 0 and succ.asExpr() = argOf(c, toArg)
      )
    )
  }
}

/**
 * Holds if a function named `name` is DEFINED in the analysed source. A name-based sanitizer model is a
 * promise about EXTERNAL (framework) code; if the codebase ships its own function of that name, the
 * dataflow engine can and must analyse its real body instead — otherwise a same-named no-op
 * (`function sanitize_text_field($x){ return $x; }`) would be silently assumed to sanitize, hiding a real
 * vulnerability (a false negative, the dangerous direction for a sanitizer).
 */
bindingset[name]
private predicate functionDefinedInSource(string name) {
  exists(Function f | f.getName().toLowerCase() = name.toLowerCase())
}

private class DataSanitizer extends Sanitizer {
  DataSanitizer() {
    exists(Call c, string sk, string nm |
      sanitizerModel(sk, nm) and
      callMatches(c, sk, nm) and
      this.asExpr() = c and
      not (sk = "function" and functionDefinedInSource(nm))
    )
  }
}

/** A function/method that HTML-escapes / strips tags but does not neutralise SQL/path/command contexts. */
extensible predicate weakXssSanitizerModel(string subjectKind, string name);

private class DataXssSanitizer extends XssSanitizer {
  DataXssSanitizer() {
    exists(Call c, string sk, string nm |
      weakXssSanitizerModel(sk, nm) and
      callMatches(c, sk, nm) and
      this.asExpr() = c and
      not (sk = "function" and functionDefinedInSource(nm))
    )
  }
}
