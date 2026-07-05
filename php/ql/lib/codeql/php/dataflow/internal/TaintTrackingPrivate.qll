/**
 * PHP-specific taint steps for the shared taint-tracking engine. Only value-transforming steps live
 * here (concatenation, interpolation, ternary/null-coalesce, string built-ins, `(string)` cast);
 * plain def-use, interprocedural flow and array/field flow are provided by the data-flow engine.
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.DataFlow
private import codeql.php.Concepts
private import codeql.php.security.FlowSources as FS
private import codeql.php.dataflow.internal.SsaImpl as Ssa
private import codeql.php.dataflow.internal.TypeInference as TI
private import DataFlowPrivate

/** Gets the `i`th (0-based) formal parameter of method `m`. */
private Php::SimpleParameter nthParam(Method m, int i) {
  result =
    rank[i + 1](Php::SimpleParameter p, int j |
      p = m.(Php::MethodDeclaration).getParameters().getChild(j)
    |
      p order by j
    )
}

/** Gets a read, inside `m`'s body, of `m`'s `i`th (0-based) formal parameter. */
private VariableAccess paramReadInBody(Method m, int i) {
  result.getName() = nthParam(m, i).getName().getChild().getValue() and
  result.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody()
}

/** Gets a value returned by method `m` (the operand of a `return` in its body). */
private Expr methodReturnValue(Method m) {
  exists(Php::ReturnStatement ret |
    ret.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody() and
    result = ret.getChild()
  )
}

/** Gets the body of any callable kind (function, method, closure, arrow). */
private AstNode anyCalleeBody(AstNode callee) {
  result = callee.(Php::FunctionDefinition).getBody() or
  result = callee.(Php::MethodDeclaration).getBody() or
  result = callee.(Php::AnonymousFunction).getBody() or
  result = callee.(Php::ArrowFunction).getBody()
}

/** Gets a formal parameter of any callable kind (function, method, closure, arrow). */
private Php::SimpleParameter anyCalleeParam(AstNode callee) {
  result = callee.(Php::FunctionDefinition).getParameters().getChild(_) or
  result = callee.(Php::MethodDeclaration).getParameters().getChild(_) or
  result = callee.(Php::AnonymousFunction).getParameters().getChild(_) or
  result = callee.(Php::ArrowFunction).getParameters().getChild(_)
}

/** Gets the value returned by any callable kind (a `return` operand, or an arrow's body expression). */
private Expr anyCalleeReturnValue(AstNode callee) {
  exists(Php::ReturnStatement ret |
    ret.(Php::AstNode).getParent+() = anyCalleeBody(callee) and result = ret.getChild()
  )
  or
  result = callee.(Php::ArrowFunction).getBody()
}

/**
 * Gets the callable that a `call_user_func` / `call_user_func_array` call `c` invokes: a string function
 * name (`call_user_func('f', …)`) or an inline closure/arrow (`call_user_func(fn(…) => …, …)`) at arg 0.
 * (Array `[obj, 'method']` and variable-held callables are a further refinement.)
 */
private AstNode cufCallee(FunctionCall c) {
  c.getName() = ["call_user_func", "call_user_func_array"] and
  (
    result.(Php::FunctionDefinition).getName().getValue() = c.getArgument(0).(StringLiteral).getValue()
    or
    result = c.getArgument(0) and
    (result instanceof Php::AnonymousFunction or result instanceof Php::ArrowFunction)
    or
    // array callable `call_user_func([$obj, 'm'], …)` / `[…, 'm']` — the resolved method.
    result = TI::arrayCallableMethod(c.getArgument(0))
  )
}

/** Gets the callable body (function/method/closure/arrow) that transitively contains `n`. */
cached
private AstNode enclosingCallableBody(AstNode n) {
  (
    result = any(Php::FunctionDefinition f).getBody() or
    result = any(Php::MethodDeclaration m).getBody() or
    result = any(Php::AnonymousFunction a).getBody() or
    result = any(Php::ArrowFunction a).getBody()
  ) and
  n.(Php::AstNode).getParent+() = result
}

/** Gets the class declaration that transitively contains `n`. */
cached
private Php::ClassDeclaration enclosingClassDecl(AstNode n) { n.(Php::AstNode).getParent+() = result }

/** Gets the `i`th formal parameter of a function or method `callee`. */
private Php::SimpleParameter calleeParam(AstNode callee, int i) {
  result = callee.(Php::FunctionDefinition).getParameters().getChild(i) or
  result = callee.(Php::MethodDeclaration).getParameters().getChild(i)
}

/** Gets the body of a function or method `callee`. */
private AstNode calleeBody(AstNode callee) {
  result = callee.(Php::FunctionDefinition).getBody() or
  result = callee.(Php::MethodDeclaration).getBody()
}

/** Gets an argument node of a call `c` (function, method, nullsafe-method, static or `new` call). */
private Php::Argument callArgumentNode(Call c) {
  result = c.(Php::FunctionCallExpression).getArguments().getChild(_) or
  result = c.(Php::MemberCallExpression).getArguments().getChild(_) or
  result = c.(Php::NullsafeMemberCallExpression).getArguments().getChild(_) or
  result = c.(Php::ScopedCallExpression).getArguments().getChild(_) or
  result = c.(Php::ObjectCreationExpression).getChild(_).(Php::Arguments).getChild(_)
}

/** Holds if call `c` passes any named argument (`f(x: …)`). */
private predicate hasNamedArgument(Call c) {
  exists(Php::Argument a | a = callArgumentNode(c) and exists(a.getName()))
}

/**
 * Holds if `call` resolves to the function/method `callee`: by name for functions, and by inferred TYPE
 * for methods — falling back to name only when the receiver type is unknown. Gating the name fallback on
 * "no inferred receiver" (as in `viableCallable`) avoids matching a same-named method on an unrelated
 * class (which would leak that class's by-ref writes into this call — a false positive).
 */
private predicate resolvesToCallee(Call call, AstNode callee) {
  callee.(Php::FunctionDefinition).getName().getValue() = call.(FunctionCall).getName()
  or
  callee = TI::inferredMethod(call)
  or
  callee.(Php::MethodDeclaration).getName().getValue() = call.(MethodCall).getMethodName() and
  not TI::hasInferredReceiver(call)
  or
  // `new C(...)` resolves to `C::__construct` (so named-args and by-ref work for constructors too).
  exists(ClassLike cls |
    cls.getName() = call.(NewExpr).getClassName() and
    callee = cls.getAMethod() and
    callee.(Php::MethodDeclaration).getName().getValue() = "__construct"
  )
}

/**
 * Holds if `a` and `b` are in the same scope: the same enclosing callable, or both at file top level
 * (no enclosing callable) in the same file.
 */
private predicate sameScope(AstNode a, AstNode b) {
  enclosingCallableBody(a) = enclosingCallableBody(b)
  or
  not exists(enclosingCallableBody(a)) and
  not exists(enclosingCallableBody(b)) and
  a.getLocation().getFile() = b.getLocation().getFile()
}

/** Holds if `e` could evaluate to an object (a variable, property, or call — not a literal). */
private predicate objectCandidate(Expr e) {
  e instanceof VariableAccess or
  e instanceof Php::MemberAccessExpression or
  e instanceof Php::MemberCallExpression or
  e instanceof Php::SubscriptExpression
}

/** Holds if expression `obj` appears in a string context (concat, interpolation, `(string)` cast). */
private predicate inStringContext(Expr obj, Expr context) {
  exists(Php::BinaryExpression b |
    b.getOperator() = "." and (b.getLeft() = obj or b.getRight() = obj) and context = b
  )
  or
  exists(Php::EncapsedString s | s.getChild(_) = obj and context = s)
  or
  exists(CastExpr cst | cst.getTypeName() = ["string", "binary"] and cst.getOperand() = obj and context = cst)
}

/** Gets a constant string value that expression `e` may hold (literal, or SSA-resolved variable). */
private string resolvedStringOf(Expr e) {
  result = e.(Php::String).getChild(_).(Php::StringContent).getValue()
  or
  result = e.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue()
  or
  exists(
    VariableAccess w, AssignExpr a, Ssa::LocalVariable v, Ssa::Definition def,
    Ssa::Cfg::BasicBlock bbw, int iw, Ssa::Cfg::BasicBlock bbr, int ir
  |
    Ssa::variableAccessAt(bbr, ir, e) and
    Ssa::Impl::ssaDefReachesRead(v, def, bbr, ir) and
    def.definesAt(v, bbw, iw) and
    Ssa::variableAccessAt(bbw, iw, w) and
    a.getLhs() = w and
    result = resolvedStringOf(a.getRhs())
  )
}

predicate defaultTaintSanitizer(DataFlow::Node node) { node instanceof Sanitizer }

cached
predicate defaultAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string model) {
  model = "" and
  (
    // GENERIC RECURSIVE PROPAGATION: taint flows from any sub-expression to its containing
    // structural/operator/access expression. This composes to arbitrary depth, so nested chains
    // like `$a[1][0]->$m()`, `($x ?? $y)[0]`, `"..{$a->b}.."` are all handled without per-case rules.
    exists(AstNode parent |
      structuralPropagator(parent) and
      nodeFrom.getAstNode() = parent.(Php::AstNode).getAFieldOrChild() and
      nodeTo.getAstNode() = parent
    )
    or
    // Subscript `$a[i]`: only the array base propagates to the result, NOT the index (a tainted
    // index does not taint the retrieved value). Chains recursively for `$a[1][2]...`.
    exists(Php::SubscriptExpression sub |
      nodeFrom.asExpr() = sub.getChild(0) and nodeTo.asExpr() = sub
    )
    or
    // Ternary `c ? a : b`: the BRANCHES propagate to the result, NOT the condition `c` (a tainted
    // condition doesn't taint the chosen value). Elvis `c ?: b` also propagates `c` (it is the value).
    exists(Php::ConditionalExpression ce |
      (
        nodeFrom.asExpr() = ce.getBody() or
        nodeFrom.asExpr() = ce.getAlternative() or
        not exists(ce.getBody()) and nodeFrom.asExpr() = ce.getCondition()
      ) and
      nodeTo.asExpr() = ce
    )
    or
    // `match ($subj) { conds => r, default => r2 }`: the value is the selected arm's RETURN, so every
    // arm return propagates to the result (over-approx: any arm may be selected). The subject only
    // selects — it does not taint the result (like a ternary condition).
    exists(Php::MatchExpression m, Php::AstNode arm |
      arm = m.getBody().getChild(_) and
      (
        nodeFrom.asExpr() = arm.(Php::MatchConditionalExpression).getReturnExpression() or
        nodeFrom.asExpr() = arm.(Php::MatchDefaultExpression).getReturnExpression()
      ) and
      nodeTo.asExpr() = m
    )
    or
    // Interpolation via heredoc body (its parts are not direct field-or-children of the heredoc).
    exists(Php::Heredoc h | nodeFrom.asExpr() = h.getValue().getChild(_) and nodeTo.asExpr() = h)
    or
    // NOTE: taint-propagating string built-ins (strtoupper/trim/substr/…) are DATA — `stepModel` rows
    // in `ext/php-builtins.model.yml`, applied by `DataStep` — not a hardcoded QL list (Phase C).
    // Assignment-as-expression (chained `$a = $b = $s`): the assignment yields its assigned value.
    exists(AssignExpr a | nodeFrom.asExpr() = a.getRhs() and nodeTo.asExpr() = a)
    or
    // `foreach ($collection as $v)` / `$k => $v` / `as [$a, $b]`: collection taints the bindings.
    exists(Php::ForeachStatement f, int i |
      i >= 1 and nodeFrom.asExpr() = f.getChild(0) and nodeTo.asExpr() = foreachBindingVar(f.getChild(i))
    )
    or
    // List/array destructuring `[$a, $b] = $rhs`: the whole RHS taints every target.
    exists(Php::AssignmentExpression a, Php::ListLiteral l |
      a.getLeft() = l and nodeFrom.asExpr() = a.getRight() and nodeTo.asExpr() = foreachBindingVar(l)
    )
    or
    // Static property `C::$p = v` taints reads of `C::$p`.
    exists(
      Php::ScopedPropertyAccessExpression w, Php::ScopedPropertyAccessExpression r,
      Php::AssignmentExpression a
    |
      a.getLeft() = w and staticPropKey(w) = staticPropKey(r) and w != r and
      nodeFrom.asExpr() = a.getRight() and nodeTo.asExpr() = r
    )
    or
    // Variable variables `$$name = v`: taint reads of variable-variables in the SAME scope (a `$$n`
    // in one function is unrelated to a `$$n` in another).
    exists(Php::DynamicVariableName w, Php::DynamicVariableName r, Php::AssignmentExpression a |
      a.getLeft() = w and sameScope(w, r) and w != r and
      nodeFrom.asExpr() = a.getRight() and nodeTo.asExpr() = r
    )
    or
    // (`global $g` cross-scope aliasing is modelled as a `jumpStep` in the data-flow layer.)
    // Closure capture `function() use ($x) { ... $x ... }`: an enclosing assignment of a captured
    // variable reaches reads of it in the closure body.
    exists(
      Php::AnonymousFunction cl, Php::AnonymousFunctionUseClause uc, VariableAccess capture,
      AssignExpr a, VariableAccess w, VariableAccess bodyRead
    |
      uc = cl.getChild() and
      capture = uc.getChild(_) and
      a.getLhs() = w and
      w.getName() = capture.getName() and
      bodyRead.getName() = capture.getName() and
      cl.getBody() = bodyRead.(Php::AstNode).getParent+() and
      not cl.getBody() = w.(Php::AstNode).getParent*() and
      // The captured assignment must live in the closure's DEFINING scope (a `use($x)` closure captures
      // `$x` from where the closure is written) — not a same-named variable in an unrelated scope/file.
      sameScope(w, cl) and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = bodyRead
    )
    or
    // By-REFERENCE closure capture `function() use (&$out) { $out = v; }`: a write to the captured
    // variable inside the closure body flows BACK to reads of it in the enclosing scope (the reference
    // makes the closure's write mutate the outer variable). The mirror of the by-value capture above.
    exists(
      Php::AnonymousFunction cl, Php::AnonymousFunctionUseClause uc, Php::ByRef capture,
      AssignExpr innerWrite, VariableAccess innerTarget, VariableAccess outerRead, string name
    |
      uc = cl.getChild() and
      capture = uc.getChild(_) and
      name = capture.getChild().(VariableAccess).getName() and
      innerWrite.getLhs() = innerTarget and
      innerTarget.getName() = name and
      cl.getBody() = innerTarget.(Php::AstNode).getParent+() and
      outerRead.getName() = name and
      not cl.getBody() = outerRead.(Php::AstNode).getParent*() and
      sameScope(outerRead, cl) and
      nodeFrom.asExpr() = innerWrite.getRhs() and
      nodeTo.asExpr() = outerRead
    )
    or
    // Arrow function auto-capture `fn() => ... $x ...`: enclosing assignment reaches the arrow body.
    exists(Php::ArrowFunction af, AssignExpr a, VariableAccess w, VariableAccess bodyRead |
      a.getLhs() = w and
      bodyRead.getName() = w.getName() and
      af.getBody() = bodyRead.(Php::AstNode).getParent*() and
      not af.getBody() = w.(Php::AstNode).getParent*() and
      // The assignment and the arrow must share a scope (the arrow captures from its enclosing scope).
      sameScope(w, af) and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = bodyRead
    )
    or
    // Variable variables to a concrete variable: `$n='v'; $$n = x;`  taints reads of `$v`.
    exists(Php::DynamicVariableName dv, Php::AssignmentExpression a, VariableAccess read |
      a.getLeft() = dv and
      read.getName() = resolvedStringOf(dv.getChild()) and
      // Same scope only — a `$$n` write in one function must not taint a same-named plain variable
      // in an unrelated function that happens to share the file.
      sameScope(dv, read) and
      nodeFrom.asExpr() = a.getRight() and
      nodeTo.asExpr() = read
    )
    or
    // Generator: `function g(){ yield $x; }` — the yielded value reaches `foreach (g() as $v)`.
    exists(Php::YieldExpression y, Php::FunctionDefinition gen, FunctionCall call, Php::ForeachStatement fe, int i |
      y.(Php::AstNode).getParent+() = gen.getBody() and
      call.getName() = gen.getName().getValue() and
      fe.getChild(0) = call and
      i >= 1 and
      nodeFrom.getAstNode() = y.getChild() and
      nodeTo.asExpr() = foreachBindingVar(fe.getChild(i))
    )
    or
    // By-reference output parameter, for FUNCTIONS and METHODS alike: `f(&$r){ $r = x; } … f($z);`
    // or `$o->m($z)` where `m(&$r){ $r = x; }` — a write to the by-ref parameter taints later reads of
    // the corresponding call argument variable. Resolution is by name (functions) or type/name (methods).
    exists(
      AstNode callee, Php::SimpleParameter p, int i, AssignExpr innerWrite, VariableAccess pWrite,
      Call call, VariableAccess callArg, VariableAccess argRead
    |
      p = calleeParam(callee, i) and
      exists(p.getReferenceModifier()) and
      innerWrite.getLhs() = pWrite and
      pWrite.getName() = p.getName().getChild().getValue() and
      pWrite.(Php::AstNode).getParent+() = calleeBody(callee) and
      resolvesToCallee(call, callee) and
      callArg = call.getArgument(i) and
      argRead.getName() = callArg.getName() and
      argRead != callArg and
      // Scope-correct (was same-file): the read and the call argument share a scope.
      sameScope(argRead, callArg) and
      nodeFrom.asExpr() = innerWrite.getRhs() and
      nodeTo.asExpr() = argRead
    )
    or
    // Instance field via `$this`: `$this->f = v` in a method taints `$this->f` reads (same field).
    exists(Php::MemberAccessExpression w, Php::MemberAccessExpression r, AssignExpr a, string fld |
      a.getLhs() = w and
      w.getObject().(VariableAccess).getName() = "this" and
      r.getObject().(VariableAccess).getName() = "this" and
      w.getName().(Php::Name).getValue() = fld and
      r.getName().(Php::Name).getValue() = fld and
      w != r and
      // Class-correct (was same-file): both `$this->f` accesses are in the SAME class, so two
      // unrelated classes sharing a field name in one file no longer cross-link.
      enclosingClassDecl(w) = enclosingClassDecl(r) and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = r
    )
    or
    // Constructor property promotion `new C($v)` with `__construct(public $f)`: the constructor argument
    // IS the promoted field, so it flows to reads of `$o->f` on the constructed object `$o = new C($v)`.
    exists(
      NewExpr ne, Method ctor, Php::PropertyPromotionParameter pp, int i,
      AssignExpr objAssign, VariableAccess objVar, Php::MemberAccessExpression fieldRead, string f
    |
      ctor = TI::exprClass(ne).getAMethod() and
      ctor.getName() = "__construct" and
      pp = ctor.(Php::MethodDeclaration).getParameters().getChild(i) and
      f = pp.getName().(Php::VariableName).getChild().getValue() and
      objAssign.getRhs() = ne and
      objAssign.getLhs() = objVar and
      fieldRead.getObject().(VariableAccess).getName() = objVar.getName() and
      fieldRead.getName().(Php::Name).getValue() = f and
      sameScope(fieldRead, objVar) and
      // the promoted parameter's name IS the field name `f`: match a named argument `f: …` or, for a
      // purely positional call, the argument at index `i` (per-call-site node — no cross-instance leak).
      (
        exists(Php::Argument a | a = callArgumentNode(ne) and a.getName().toString() = f |
          nodeFrom.asExpr() = a.getChild()
        )
        or
        not hasNamedArgument(ne) and nodeFrom.asExpr() = ne.getArgument(i)
      ) and
      nodeTo.asExpr() = fieldRead
    )
    or
    // Magic `__toString`: an object used in string context (concat, interpolation, `(string)` cast)
    // invokes `__toString()`; its returned value taints that context. Type-agnostic (works for
    // parameters/fields/returns of unknown type, e.g. a cast inside `__wakeup`), bounded because it
    // only carries taint when some `__toString` actually returns tainted data. `obj` must be an
    // object-candidate expression (variable/property/call), never a plain string literal.
    exists(Method ts, Expr ctx, Expr obj |
      ts.getName() = "__toString" and
      inStringContext(obj, ctx) and
      objectCandidate(obj) and
      nodeFrom.asExpr() = methodReturnValue(ts) and
      nodeTo.asExpr() = ctx and
      // Precise when the object's class is inferred; type-agnostic fallback otherwise (bounded).
      (ts = TI::exprClass(obj).getAMethod() or not exists(TI::exprClass(obj)))
    )
    or
    // Magic `__get`: `$o->prop` on an object with `__get` returns `__get`'s value.
    exists(VariableAccess obj, ClassLike c, Method g, Php::MemberAccessExpression ma |
      c = TI::exprClass(obj) and
      g = c.getAMethod() and
      g.getName() = "__get" and
      ma.getObject() = obj and
      nodeFrom.asExpr() = methodReturnValue(g) and
      nodeTo.asExpr() = ma
    )
    or
    // Magic `__call`: `$o->m($x)` resolving to `__call` — the return value flows to the call site,
    // and the argument list flows to `__call`'s 2nd parameter (`$arguments`).
    exists(VariableAccess obj, ClassLike c, Method mc, Php::MemberCallExpression call |
      c = TI::exprClass(obj) and
      mc = c.getAMethod() and
      mc.getName() = "__call" and
      call.getObject() = obj and
      nodeFrom.asExpr() = methodReturnValue(mc) and
      nodeTo.asExpr() = call
    )
    or
    exists(VariableAccess obj, ClassLike c, Method mc, Php::MemberCallExpression call |
      c = TI::exprClass(obj) and
      mc = c.getAMethod() and
      mc.getName() = "__call" and
      call.getObject() = obj and
      nodeFrom.getAstNode() = call.getArguments().getChild(_) and
      nodeTo.asExpr() = paramReadInBody(mc, 1)
    )
    or
    // Magic `__set`: `$o->p = v` invokes `__set($name, $value)`; `v` flows to `$value` reads. Type-
    // agnostic (bounded because it only matters when `v` is tainted).
    exists(Method st, AssignExpr a, Php::MemberAccessExpression ma |
      st.getName() = "__set" and
      a.getLhs() = ma and
      objectCandidate(ma.getObject()) and
      // Type-gated like `__toString`: dispatch to the receiver's `__set` when its class is inferred,
      // falling back to any `__set` only when the type is unknown — so `$plain->x = $v` on a class with
      // no `__set` is not routed into an unrelated class's `__set` (a false positive).
      (st = TI::exprClass(ma.getObject()).getAMethod() or not exists(TI::exprClass(ma.getObject()))) and
      nodeFrom.asExpr() = a.getRhs() and
      nodeTo.asExpr() = paramReadInBody(st, 1)
    )
    or
    // Magic `__callStatic`: `C::m($x)` resolving to `__callStatic` — return flows to the call site.
    exists(ClassLike c, Method cs, Php::ScopedCallExpression call |
      c.getName() = call.getScope().(Php::Name).getValue() and
      cs = c.getAMethod() and
      cs.getName() = "__callStatic" and
      nodeFrom.asExpr() = methodReturnValue(cs) and
      nodeTo.asExpr() = call
    )
    or
    // (Setter mutation flow-back — `$o->set($a)` storing into `$this->f`, later `$o->f` reads — is now
    // handled generically by the field-content model + receiver-as-argument + PostUpdate in
    // DataFlowPrivate, so no hand-written setter step here.)
    // (Constructor mutation flow-back — `$o = new C($a)` storing into `$this->f`, later `$o->f` reads —
    // is now handled generically by the InitializeReturnNode + field-content model in DataFlowPrivate.)
    // NOTE: `$GLOBALS['k']` is handled cross-file as a value-preserving `jumpStep` in DataFlowPrivate
    // (a genuine superglobal), so no same-file taint step is needed here (B.6).

    // Reference alias `$b =& $a`: assigning to one alias taints reads of the other (same file).
    exists(
      Php::ReferenceAssignmentExpression ra, AssignExpr av, VariableAccess aw, VariableAccess br,
      string n1, string n2
    |
      n1 = ra.getLeft().(VariableAccess).getName() and
      n2 = ra.getRight().(VariableAccess).getName() and
      av.getLhs() = aw and
      (aw.getName() = n1 and br.getName() = n2 or aw.getName() = n2 and br.getName() = n1) and
      // A `$b =& $a` alias is scope-local: require the alias, the write and the read to share a scope,
      // not merely the same file (same-named locals in unrelated functions must not cross-link).
      sameScope(ra, aw) and
      sameScope(aw, br) and
      nodeFrom.asExpr() = av.getRhs() and
      nodeTo.asExpr() = br
    )
    or
    // Exception message reflection: `throw new E($x)` … `catch ($e) { … $e->getMessage() … }` — the
    // constructor argument reaches the caught exception's message/string accessors.
    exists(
      Php::TryStatement t, Php::ThrowExpression th, NewExpr ne, Php::CatchClause cc, MethodCall gm,
      VariableAccess ev
    |
      th.(Php::AstNode).getParent+() = t.getBody() and
      ne = th.getChild() and
      cc = t.getChild(_) and
      gm.getReceiver() = ev and
      ev.getName() = cc.getName().getChild().getValue() and
      gm.(Php::AstNode).getParent+() = cc.getBody() and
      gm.getMethodName() = ["getMessage", "getTraceAsString", "__toString"] and
      nodeFrom.asExpr() = ne.getAnArgument() and
      nodeTo.asExpr() = gm
    )
    or
    // Higher-order callback: `array_map(function($x){…}, $arr)` / `usort`/`call_user_func` — the data
    // argument reaches the inline closure's parameter. Handles both argument orders (callback-first
    // and array-first) by pairing any inline closure with any other argument.
    exists(FunctionCall c, Php::AnonymousFunction cl, int i, int j, string pn, VariableAccess pRead |
      c.getName() =
        [
          "array_map", "array_walk", "array_filter", "array_reduce", "usort", "uasort", "uksort",
          "call_user_func", "call_user_func_array"
        ] and
      cl = c.getArgument(i) and
      exists(c.getArgument(j)) and
      j != i and
      pn = cl.getParameters().getChild(_).(Php::SimpleParameter).getName().getChild().getValue() and
      pRead.getName() = pn and
      pRead.(Php::AstNode).getParent+() = cl.getBody() and
      nodeFrom.asExpr() = c.getArgument(j) and
      nodeTo.asExpr() = pRead
    )
    or
    // `call_user_func[_array]` — the invoked callable's RETURN flows to the call result.
    exists(FunctionCall c, AstNode callee |
      callee = cufCallee(c) and
      nodeFrom.asExpr() = anyCalleeReturnValue(callee) and
      nodeTo.asExpr() = c
    )
    or
    // `call_user_func[_array]` — each passed argument flows to the callable's parameters. For
    // `call_user_func` the passed args are positions 1.. ; for `call_user_func_array` they are the
    // elements of the array at position 1 (element→position not tracked — recall-first, whole array).
    exists(FunctionCall c, AstNode callee, VariableAccess pRead |
      callee = cufCallee(c) and
      pRead.getName() = anyCalleeParam(callee).getName().getChild().getValue() and
      // getParent* (reflexive) so an arrow whose whole body IS the parameter read (`fn($a) => $a`) matches.
      pRead.(Php::AstNode).getParent*() = anyCalleeBody(callee) and
      (
        c.getName() = "call_user_func" and nodeFrom.asExpr() = c.getArgument(any(int k | k >= 1))
        or
        c.getName() = "call_user_func_array" and
        nodeFrom.asExpr() =
          c.getArgument(1).(Php::ArrayCreationExpression).getChild(_).(Php::ArrayElementInitializer).getChild(_)
      ) and
      nodeTo.asExpr() = pRead
    )
    or
    // Argument unpacking / spread `f(...$args)`: the unpacked array reaches the callee's parameters
    // (element→position is not tracked, so — recall-first — the whole array reaches every parameter).
    // Works for functions and methods (callee resolved by name / inferred type).
    exists(Call call, Php::VariadicUnpacking vu, AstNode callee, VariableAccess pRead |
      vu = callArgumentNode(call).getChild() and
      resolvesToCallee(call, callee) and
      pRead.getName() = calleeParam(callee, _).getName().getChild().getValue() and
      pRead.(Php::AstNode).getParent+() = calleeBody(callee) and
      nodeFrom.asExpr() = vu.getChild() and
      nodeTo.asExpr() = pRead
    )
    or
    // NOTE: array higher-order data→result (array_map/array_filter/…) is DATA — `stepModel` rows in
    // `ext/php-builtins.model.yml` (any arg → return), applied by `DataStep` (Phase C). The inline-
    // closure step above (routing data INTO the callback body) stays engine logic.
    // `parse_str($tainted, $out)` / `mb_parse_str`: the by-ref output array is populated from the
    // tainted input string, so reads of `$out` in the same scope are tainted.
    exists(FunctionCall c, VariableAccess outArg, VariableAccess outRead |
      c.getName() = ["parse_str", "mb_parse_str"] and
      outArg = c.getArgument(1) and
      outRead.getName() = outArg.getName() and
      outRead != outArg and
      sameScope(outRead, outArg) and
      nodeFrom.asExpr() = c.getArgument(0) and
      nodeTo.asExpr() = outRead
    )
    or
    // Named arguments (PHP 8): `f(cmd: $v)` / `$o->m(cmd: $v)` — the value reaches the parameter *named*
    // `cmd` in the callee, independent of positional order, for functions AND methods (callee resolved
    // by name / inferred type, as elsewhere).
    exists(
      Call c, Php::Argument arg, AstNode callee, Php::SimpleParameter p, VariableAccess pRead, string pname
    |
      arg = callArgumentNode(c) and
      pname = arg.getName().toString() and
      resolvesToCallee(c, callee) and
      p = calleeParam(callee, _) and
      p.getName().getChild().getValue() = pname and
      pRead.getName() = pname and
      pRead.(Php::AstNode).getParent+() = calleeBody(callee) and
      nodeFrom.asExpr() = arg.getChild() and
      nodeTo.asExpr() = pRead
    )
    or
    // Extensible steps contributed by QL subclasses or data-extension model rows.
    any(AdditionalTaintStep s).step(nodeFrom, nodeTo)
  )
}

/**
 * Holds if `e` is a structural / operator / access expression through which taint flows generically
 * from any of its operands to `e` itself. Enumerated once; composition gives recursive coverage of
 * arbitrarily nested syntax. (Plain function calls are excluded — they use summaries/interproc.)
 */
private predicate structuralPropagator(AstNode e) {
  e instanceof Php::MemberAccessExpression or
  e instanceof Php::NullsafeMemberAccessExpression or
  // NOTE: method/static CALL expressions are deliberately NOT here. A call's argument→return flow is
  // decided by the callee body (real interprocedural summaries via `viableCallable`) or by a Models-as-
  // Data `stepModel` row for library methods — never a blanket "every argument taints the result", which
  // would defeat every method-based sanitizer (e.g. `$db->quote($x)`, `$purifier->purify($x)`).
  e instanceof Php::ScopedPropertyAccessExpression or
  e instanceof Php::CastExpression or
  e instanceof Php::UnaryOpExpression or
  e instanceof Php::BinaryExpression or
  // `$x .= v` / `$x += v` — the augmented expression is tainted if the old value (left) or `v` (right)
  // is; combined with the augmented-assign read/def model in SsaImpl/DataFlowPrivate (AUDIT.md A.2).
  e instanceof Php::AugmentedAssignmentExpression or
  e instanceof Php::ParenthesizedExpression or
  e instanceof Php::EncapsedString or
  e instanceof Php::ArrayCreationExpression or
  e instanceof Php::ArrayElementInitializer or
  e instanceof Php::Pair or
  e instanceof Php::Argument or
  e instanceof Php::Arguments or
  e instanceof Php::VariadicUnpacking or
  e instanceof Php::ListLiteral
}

/** Gets a variable bound by a destructuring/foreach target (bare var, `$k => $v` pair, list pattern). */
private VariableAccess foreachBindingVar(AstNode t) {
  result = t
  or
  result = foreachBindingVar(t.(Php::Pair).getChild(_))
  or
  result = foreachBindingVar(t.(Php::ListLiteral).getChild(_))
  or
  // by-reference value binding `foreach (... as &$v)`.
  result = foreachBindingVar(t.(Php::ByRef).getChild())
}

/** Gets a `class::$prop` key identifying a static property access. */
private string staticPropKey(Php::ScopedPropertyAccessExpression sp) {
  exists(string prop | prop = sp.getName().(Php::VariableName).getChild().getValue() |
    // explicit class name `C::$p`
    result = sp.getScope().(Php::Name).getValue() + "::" + prop
    or
    // `self::$p` / `static::$p` — normalize to the enclosing class so a same-class write/read connect.
    sp.getScope().(Php::RelativeScope).toString() = ["self", "static"] and
    result = enclosingClassDecl(sp).getName().getValue() + "::" + prop
  )
}

bindingset[node]
predicate defaultImplicitTaintRead(DataFlow::Node node, DataFlow::ContentSet c) {
  // Array/property inheritance of taint is handled by the read steps in `defaultAdditionalTaintStep`.
  none()
}

predicate speculativeTaintStep(DataFlow::Node src, DataFlow::Node sink) { none() }
