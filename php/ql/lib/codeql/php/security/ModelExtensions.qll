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

/** A function/method whose result is a remote source of `sourceType`. */
extensible predicate sourceModel(string subjectKind, string name, string sourceType);

/** An argument (`argIndex`) of a function/method that is a `vulnKind` sink. */
extensible predicate sinkModel(string subjectKind, string name, int argIndex, string vulnKind);

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
 * A method that sanitizes ONLY when called on a receiver of class `className` (e.g. `wpdb::prepare`
 * is safe, but a user's custom `MyClass::prepare` is not). Avoids the false-negatives of matching a
 * sanitizer purely by method name. Receiver type is resolved via SSA (`$o = new C()`) or, for the
 * common framework globals, by convention (`global $wpdb`).
 */
extensible predicate typedSanitizerModel(string className, string methodName);

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

private class TypedSanitizer extends Sanitizer {
  TypedSanitizer() {
    exists(MethodCall c, string cls |
      typedSanitizerModel(cls, c.getMethodName()) and
      receiverClassName(c.getReceiver()) = cls and
      this.asExpr() = c
    )
  }
}

/** Gets the `i`th argument of call `c`, or any argument when `i = -1`. */
private Expr argOf(Call c, int i) {
  i >= 0 and result = c.getArgument(i)
  or
  i = -1 and result = c.getAnArgument()
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

private class DataSanitizer extends Sanitizer {
  DataSanitizer() {
    exists(Call c, string sk, string nm |
      sanitizerModel(sk, nm) and callMatches(c, sk, nm) and this.asExpr() = c
    )
  }
}
