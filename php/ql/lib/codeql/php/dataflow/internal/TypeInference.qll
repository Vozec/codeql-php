/**
 * Lightweight type inference for PHP object expressions.
 *
 * Computes, for an expression, the class(es) it may be an instance of, using: `new C()`, `$this`,
 * type-declared parameters (`function f(Foo $x)`), SSA assignment propagation, and type-declared
 * return values. This is the foundation for TYPE-based call resolution (replacing name-only
 * dispatch) and receiver-typed sanitizers. It is an over-approximation (recall-first): when a type
 * cannot be inferred, callers fall back to name-based resolution.
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.dataflow.internal.SsaImpl as Ssa

/** Gets the class a type-declaration node `t` denotes (`Foo`, `?Foo`, namespace-aware). */
private ClassLike typeNodeClass(AstNode t) {
  result = resolveClassReference(t.(Php::NamedType).getChild().(AstNode))
  or
  result = typeNodeClass(t.(Php::OptionalType).getChild())
}

/**
 * Holds if parameter `p` is declared with a CLASS type (so it is a dependency-injected service or a
 * model-bound object, NOT a scalar route parameter). Untyped params and scalar-typed params
 * (`int`/`string`/…, which don't resolve to a class) do not hold — those are the route-parameter shape.
 */
predicate hasClassParameterType(Php::SimpleParameter p) { exists(typeNodeClass(p.getType())) }

/** Gets the class whose method body (transitively) encloses `n` — the type of `$this` inside it. */
private ClassLike enclosingClass(AstNode n) {
  exists(Method m |
    n.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody() and
    result = m.getDeclaringType()
  )
}

/** Gets the variable-write that an SSA analysis says reaches the read `read`. */
private VariableAccess ssaWriteReaching(VariableAccess read) {
  exists(
    Ssa::LocalVariable v, Ssa::Definition def, Ssa::Cfg::BasicBlock bbw, int iw,
    Ssa::Cfg::BasicBlock bbr, int ir
  |
    Ssa::variableAccessAt(bbr, ir, read) and
    Ssa::Impl::ssaDefReachesRead(v, def, bbr, ir) and
    def.definesAt(v, bbw, iw) and
    Ssa::variableAccessAt(bbw, iw, result)
  )
}

/** Gets the declared return type's class of a function/method declaration, if any. */
private ClassLike declaredReturnClass(Callable c) {
  result = typeNodeClass(c.(Php::FunctionDefinition).getReturnType())
  or
  result = typeNodeClass(c.(Php::MethodDeclaration).getReturnType())
}

/** Gets a class equal to `c` or one of its ancestors/traits (where members may be declared). */
private ClassLike classOrAncestor(ClassLike c) { result = c or result = c.getAnAncestor() }

/** Gets a member node in the raw body of class/trait `c`. */
private AstNode classBodyMember(ClassLike c) {
  result = c.(Php::ClassDeclaration).getBody().getChild(_) or
  result = c.(Php::TraitDeclaration).getBody().getChild(_)
}

/** Gets the short (last `\`-segment) name written in a type-declaration node `t` — WITHOUT requiring the
 *  class to be declared/extracted. Lets typed models match framework classes that live in `vendor/`. */
string typeNodeName(AstNode t) {
  exists(AstNode nm | nm = t.(Php::NamedType).getChild() |
    result = nm.(Php::Name).getValue()
    or
    result = nm.(Php::QualifiedName).getChild().(Php::Name).getValue()
  )
  or
  result = typeNodeName(t.(Php::OptionalType).getChild())
}

/** Gets the declared/promoted type NAME (short, annotation-based) of `$this->name`. */
private string thisPropertyTypeName(Php::MemberAccessExpression ma, string name) {
  ma.getObject().(VariableAccess).getName() = "this" and
  name = ma.getName().(Php::Name).getValue() and
  exists(ClassLike c | c = enclosingClass(ma) |
    exists(Php::PropertyDeclaration pd, Php::PropertyElement pe |
      pd = classBodyMember(classOrAncestor(c)) and
      pe = pd.getChild(_) and
      pe.getName().getChild().getValue() = name and
      result = typeNodeName(pd.getType())
    )
    or
    exists(Method ctor, Php::PropertyPromotionParameter pp |
      ctor = classOrAncestor(c).getADeclaredMethod() and
      ctor.getName() = "__construct" and
      pp.(Php::AstNode).getParent+() = ctor.(Php::MethodDeclaration) and
      pp.getName().(Php::VariableName).getChild().getValue() = name and
      result = typeNodeName(pp.getType())
    )
  )
}

/**
 * Gets the short type NAME an expression is annotated with — a type-declared parameter (`function
 * (Request $r)`), a `$this->prop` property type, `new C()`, or propagated through SSA assignment —
 * WITHOUT requiring the class to be declared. Complements `exprClass` (which needs a declared class), so
 * typed source/sink/sanitizer models fire on framework classes that live in an un-extracted `vendor/`.
 */
cached
string exprTypeName(Expr e) {
  exists(Php::ObjectCreationExpression oc | oc = e |
    result = oc.getChild(_).(Php::Name).getValue()
    or
    result = oc.getChild(_).(Php::QualifiedName).getChild().(Php::Name).getValue()
  )
  or
  exists(VariableAccess w, Php::SimpleParameter p |
    w = ssaWriteReaching(e) and p.getName() = w and result = typeNodeName(p.getType())
  )
  or
  result = thisPropertyTypeName(e, _)
  or
  exists(VariableAccess w, AssignExpr a |
    w = ssaWriteReaching(e) and a.getLhs() = w and result = exprTypeName(a.getRhs())
  )
}

/** Gets the declared class-type of property `name` on class `c` (declared or constructor-promoted). */
private ClassLike propertyClass(ClassLike c, string name) {
  exists(ClassLike d, Php::PropertyDeclaration pd, Php::PropertyElement pe |
    d = classOrAncestor(c) and
    pd = classBodyMember(d) and
    pe = pd.getChild(_) and
    pe.getName().getChild().getValue() = name and
    result = typeNodeClass(pd.getType())
  )
  or
  exists(ClassLike d, Method ctor, Php::PropertyPromotionParameter pp |
    d = classOrAncestor(c) and
    ctor = d.getADeclaredMethod() and
    ctor.getName() = "__construct" and
    pp.(Php::AstNode).getParent+() = ctor.(Php::MethodDeclaration) and
    pp.getName().(Php::VariableName).getChild().getValue() = name and
    result = typeNodeClass(pp.getType())
  )
}

/** Holds if method `m`'s body returns `$this` (fluent interface). */
private predicate returnsThis(Method m) {
  exists(Php::ReturnStatement ret, Php::VariableName v |
    ret.(Php::AstNode).getParent+() = m.(Php::MethodDeclaration).getBody() and
    v = ret.getChild() and
    v.getChild().getValue() = "this"
  )
}

/**
 * Gets a class that expression `e` may be an instance of. Recursive fixpoint over SSA and returns;
 * `cached` because it is consumed by the (heavily reused) call graph.
 */
cached
ClassLike exprClass(Expr e) {
  // `new C(...)` — namespace-aware.
  result = resolveClassReference(e.(Php::ObjectCreationExpression).getChild(_).(AstNode))
  or
  // `new self()` / `new static()` inside a method resolve to the enclosing class (idiomatic factories).
  e.(Php::ObjectCreationExpression).getChild(_).(Php::Name).getValue() = ["self", "static"] and
  result = enclosingClass(e)
  or
  // `$this` inside a method resolves to the declaring class (and its subclasses inherit the type).
  e.(VariableAccess).getName() = "this" and result = enclosingClass(e)
  or
  // A read whose reaching SSA write is a type-declared parameter, or an assignment from a typed rhs.
  exists(VariableAccess w | w = ssaWriteReaching(e) |
    exists(Php::SimpleParameter p | p.getName() = w and result = typeNodeClass(p.getType()))
    or
    exists(AssignExpr a | a.getLhs() = w and result = exprClass(a.getRhs()))
  )
  or
  // A call to a function/method with a declared object return type.
  exists(FunctionCall fc | fc = e and result = declaredReturnClass(callTarget(fc)))
  or
  exists(MethodCall mc | mc = e and result = declaredReturnClass(inferredMethod(mc)))
  or
  // Fluent `return $this`: `$o->m()` has the class of `$o` when `m` returns `$this`.
  exists(MethodCall mc | mc = e and returnsThis(inferredMethod(mc)) and result = exprClass(mc.getReceiver()))
  or
  // `$obj->prop` where the class of `$obj` declares `Type $prop`.
  exists(Php::MemberAccessExpression ma |
    ma = e and result = propertyClass(exprClass(ma.getObject()), ma.getName().(Php::Name).getValue())
  )
  or
  // `clone $x` has the same class as `$x`.
  result = exprClass(e.(Php::CloneExpression).getChild())
  or
  // Dynamic instantiation `new $c()` where `$c` resolves (via SSA) to a class-name string literal.
  exists(VariableAccess cv, VariableAccess w, AssignExpr a |
    cv = e.(Php::ObjectCreationExpression).getChild(_) and
    w = ssaWriteReaching(cv) and
    a.getLhs() = w and
    result.getName() =
      [
        a.getRhs().(Php::String).getChild(_).(Php::StringContent).getValue(),
        a.getRhs().(Php::EncapsedString).getChild(_).(Php::StringContent).getValue()
      ]
  )
}

/** Gets the function a plain call `fc` targets by name (used only for return-type inference). */
private Callable callTarget(FunctionCall fc) {
  result.(Php::FunctionDefinition).getName().getValue() = fc.getName()
}

/**
 * Gets the method name dispatched to by `mc`: its literal name, or — for a variable method name
 * `$o->$m()` — the constant string that `$m` resolves to via SSA (`$m = 'run'; $o->$m()`).
 */
private string methodNameOf(MethodCall mc) {
  result = mc.getMethodName()
  or
  exists(VariableAccess mv, VariableAccess w, AssignExpr a |
    mc.(Php::MemberCallExpression).getName() = mv and
    w = ssaWriteReaching(mv) and
    a.getLhs() = w and
    result = a.getRhs().(Php::String).getChild(_).(Php::StringContent).getValue()
  )
}

/**
 * Gets the method that a `$recv->m(...)` call dispatches to, resolved by the inferred class of the
 * receiver (and its ancestors/traits via `getAMethod`). Empty when the receiver type is unknown —
 * callers then fall back to name-based resolution.
 */
cached
Method inferredMethod(MethodCall mc) {
  exists(ClassLike c |
    c = exprClass(mc.getReceiver()) and
    result = c.getAMethod() and
    result.getName() = methodNameOf(mc)
  )
  or
  // Virtual dispatch: the receiver's inferred type is a base class or interface (e.g. a parameter typed
  // `I $o`), but the concrete implementation lives on a subtype/implementor. Dispatch to any subtype's
  // declared method of that name (recall-first — the runtime object may be any implementor).
  exists(ClassLike base, ClassLike sub |
    base = exprClass(mc.getReceiver()) and
    base = sub.getAnAncestor() and
    result = sub.getADeclaredMethod() and
    result.getName() = methodNameOf(mc)
  )
}

/** Holds if the receiver type of method call `mc` is known (so name-based fallback is unnecessary). */
cached
predicate hasInferredReceiver(MethodCall mc) { exists(exprClass(mc.getReceiver())) }

/**
 * Gets the method denoted by a 2-element array callable `[receiver, 'name']`:
 *  - instance callable `[$obj, 'm']` — resolved by the receiver's inferred class (with virtual
 *    dispatch to subtype implementors, recall-first);
 *  - class-name callable `['C', 'm']` — resolved by the literal class name.
 * Models the PHP `[obj|class, method]` callable so it participates in first-class-callable flow
 * (`lambdaCreation`) and the `call_user_func([$o,'m'], …)` step, without enumerating call sites.
 */
cached
Method arrayCallableMethod(Php::ArrayCreationExpression arr) {
  exists(Expr recv, string name |
    recv = arr.getChild(0).(Php::ArrayElementInitializer).getChild(0) and
    name = arr.getChild(1).(Php::ArrayElementInitializer).getChild(0).(StringLiteral).getValue() and
    result.getName() = name and
    (
      // instance `[$obj, 'm']`
      result = exprClass(recv).getAMethod()
      or
      // virtual dispatch: receiver typed as a base/interface, implementation on a subtype
      exists(ClassLike sub | exprClass(recv) = sub.getAnAncestor() and result = sub.getADeclaredMethod())
      or
      // class-name string `['C', 'm']`
      exists(ClassLike c | c.getName() = recv.(StringLiteral).getValue() and result = c.getAMethod())
    )
  )
}

/**
 * Gets the method a static call `C::m()` / `self::m()` / `static::m()` / `parent::m()` dispatches to,
 * resolving the scope to a concrete class (namespace-aware for explicit class names).
 */
cached
Method staticInferredMethod(StaticMethodCall sc) {
  exists(ClassLike c |
    result = c.getAMethod() and
    result.getName() = sc.getMethodName() and
    (
      sc.(Php::ScopedCallExpression).getScope().(Php::RelativeScope).toString() = ["self", "static"] and
      c = enclosingClass(sc)
      or
      sc.(Php::ScopedCallExpression).getScope().(Php::RelativeScope).toString() = "parent" and
      c = enclosingClass(sc).getASuperType()
      or
      // Explicit class name (namespace-aware); empty for relative scopes, which is fine.
      c = resolveClassReference(sc.(Php::ScopedCallExpression).getScope().(AstNode))
    )
  )
}

/** Holds if the scope class of static call `sc` is resolved (so name-based fallback is unnecessary). */
cached
predicate hasInferredStaticTarget(StaticMethodCall sc) { exists(staticInferredMethod(sc)) }
