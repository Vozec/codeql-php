/**
 * PHP-specific implementation of the shared data-flow `InputSig`.
 * Provides the call graph, parameter/argument/return model, local flow and content steps that the
 * shared engine composes into a field-sensitive, interprocedural, path-explaining data-flow graph.
 */

private import codeql.util.Unit
private import codeql.dataflow.DataFlow
private import codeql.Locations
private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.controlflow.ControlFlowGraph as Cfg
private import codeql.php.dataflow.internal.SsaImpl as Ssa
private import codeql.php.dataflow.internal.TypeInference as TI
private import DataFlowPublic

class DataFlowSecondLevelScope = Unit;

/** Gets a `$this` variable access inside method `m`'s body. */
private VariableAccess thisAccess(Php::MethodDeclaration m) {
  result.getName() = "this" and result.(Php::AstNode).getParent+() = m.getBody()
}

/**
 * Holds if CFG node `n` needs a post-update node: every call argument (including the receiver at
 * position -1) and every object that is the base of a field store (`$o->f = v`, `$o->f .= v`) — a
 * mutation applied there must be observable at later reads of the same object.
 */
private predicate needsPostUpdate(Cfg::CfgNode n) {
  n = any(DataFlowCall c).getArgumentCfgNode(_)
  or
  exists(AssignExpr a, Php::MemberAccessExpression m | a.getLhs() = m and n.getAstNode() = m.getObject())
  or
  exists(Php::AugmentedAssignmentExpression a, Php::MemberAccessExpression m |
    a.getLeft() = m and n.getAstNode() = m.getObject()
  )
  or
  // base of an array store `$a[k] = v` — so an appended/keyed element folds onto the base's post-update
  // (interprocedural array-field mutation, e.g. a method doing `$this->items[] = $v`).
  exists(AssignExpr a, Php::SubscriptExpression sub | a.getLhs() = sub and n.getAstNode() = sub.getChild(0))
  or
  // The OBJECT of a nested store base (`$o` in `$o->f->g = v` / `$o->f[] = v`) also needs a post-update,
  // so the inner access's mutation folds up one more level onto `$o` — the two-level interprocedural
  // carry-out (a method doing `$this->items[] = $v` or `$this->other->f = $v`).
  exists(Php::MemberAccessExpression m | m = nestedStoreBase() and n.getAstNode() = m.getObject())
}

/** Gets a member access that is the base of a nested store (`$o->f->g = v` or `$o->f[] = v`). */
private Php::MemberAccessExpression nestedStoreBase() {
  exists(AssignExpr a, Php::MemberAccessExpression outer | a.getLhs() = outer and result = outer.getObject())
  or
  exists(AssignExpr a, Php::SubscriptExpression sub | a.getLhs() = sub and result = sub.getChild(0))
}

newtype TNode =
  TExprNode(Cfg::CfgNode n) or
  TThisParameterNode(Php::MethodDeclaration m) { exists(thisAccess(m)) } or
  TExprPostUpdateNode(Cfg::CfgNode n) { needsPostUpdate(n) }

// --- Callables and calls ------------------------------------------------------------------------

private Php::FormalParameters formalParametersOf(Cfg::CfgScope c) {
  result = c.(Php::FunctionDefinition).getParameters() or
  result = c.(Php::MethodDeclaration).getParameters() or
  result = c.(Php::AnonymousFunction).getParameters() or
  result = c.(Php::ArrowFunction).getParameters()
}

private Php::VariableName parameterName(AstNode param) {
  result = param.(Php::SimpleParameter).getName() or
  result = param.(Php::VariadicParameter).getName() or
  result = param.(Php::PropertyPromotionParameter).getName().(Php::VariableName)
}

/** A callable that data can flow into and out of: a function, method, closure, or the file top level. */
class DataFlowCallable instanceof Cfg::CfgScope {
  string toString() { result = super.toString() }

  Location getLocation() { result = super.getLocation() }

  /** Gets the name used to resolve calls to this callable (functions and methods). */
  string getName() {
    result = this.(Php::FunctionDefinition).getName().getValue() or
    result = this.(Php::MethodDeclaration).getName().getValue()
  }

  /** Gets the CFG node of this callable's `pos`th parameter. */
  Cfg::CfgNode getParameterCfgNode(int pos) {
    result.getAstNode() = parameterName(formalParametersOf(this).getChild(pos))
  }

  int totalorder() { none() }
}

/** A call site. */
class DataFlowCall instanceof Cfg::CfgNode {
  Call c;

  DataFlowCall() { c = super.getAstNode() }

  /** Gets the underlying call expression. */
  Call getCall() { result = c }

  string toString() { result = super.toString() }

  Location getLocation() { result = super.getLocation() }

  /** Gets the callee name (function or method name). */
  string getName() {
    result = c.(FunctionCall).getName() or
    result = c.(MethodCall).getMethodName() or
    result = c.(StaticMethodCall).getMethodName()
  }

  DataFlowCallable getEnclosingCallable() { result = super.getScope() }

  /** Gets the CFG node of this call's `pos`th argument (`pos = -1` is the `$o->m()` receiver). */
  Cfg::CfgNode getArgumentCfgNode(int pos) {
    pos >= 0 and
    result.getAstNode() = c.getArgument(pos) and
    // Named arguments (`f(x: $v)`) are routed by name via a taint step, so exclude them here to avoid
    // mis-mapping to the parameter at their textual position.
    not exists(Php::Argument a |
      a.getChild() = c.getArgument(pos) and exists(a.getName().(Php::Name))
    )
    or
    // The receiver of `$o->m(...)` is the `this` argument (position -1).
    pos = -1 and result.getAstNode() = c.(MethodCall).getReceiver()
  }

  /** Gets the closure directly invoked by this call, for an IIFE `(function(){...})(...)`. */
  DataFlowCallable getInlineCallee() {
    exists(Php::ParenthesizedExpression p |
      p = c.(Php::FunctionCallExpression).getFunction()
    |
      result = p.getChild().(Php::AnonymousFunction)
      or
      result = p.getChild().(Php::ArrowFunction)
    )
  }

  /** Gets the constructor invoked by `new C(...)`. */
  DataFlowCallable getConstructCallee() {
    exists(ClassLike cls |
      cls.getName() = c.(NewExpr).getClassName() and
      result = cls.getAMethod() and
      result.(Method).getName() = "__construct"
    )
  }

  /** Gets the method this call dispatches to via the INFERRED class of its receiver (type-based). */
  DataFlowCallable getTypedCallee() { exists(MethodCall mc | mc = c and result = TI::inferredMethod(mc)) }

  /** Holds if the receiver's class is inferred, so name-based fallback is not needed. */
  predicate hasTypedReceiver() { exists(MethodCall mc | mc = c and TI::hasInferredReceiver(mc)) }

  /** Gets the method a static call `C::m`/`self::`/`static::`/`parent::` dispatches to (type-based). */
  DataFlowCallable getStaticTypedCallee() {
    exists(StaticMethodCall sc | sc = c and result = TI::staticInferredMethod(sc))
  }

  /** Holds if the static call's scope class is resolved, so name-based fallback is not needed. */
  predicate hasStaticTypedTarget() {
    exists(StaticMethodCall sc | sc = c and TI::hasInferredStaticTarget(sc))
  }

  /**
   * Gets the function invoked by `$fn(...)` when `$fn` resolves (via SSA) to a constant string function
   * name — a string-callable, e.g. `$fn = 'strtoupper'; $fn($x)`. Dispatch by name (like a plain call).
   */
  DataFlowCallable getStringNamedCallee() {
    exists(
      VariableAccess fnvar, VariableAccess w, AssignExpr a, string fname, Ssa::LocalVariable v,
      Ssa::Definition def, Ssa::Cfg::BasicBlock bbw, int iw, Ssa::Cfg::BasicBlock bbr, int ir
    |
      c.(Php::FunctionCallExpression).getFunction() = fnvar and
      Ssa::variableAccessAt(bbr, ir, fnvar) and
      Ssa::Impl::ssaDefReachesRead(v, def, bbr, ir) and
      def.definesAt(v, bbw, iw) and
      Ssa::variableAccessAt(bbw, iw, w) and
      a.getLhs() = w and
      fname = a.getRhs().(Php::String).getChild(_).(Php::StringContent).getValue() and
      result.getName() = fname
    )
  }

  /** Gets the `__invoke` method invoked by `$obj(...)` when `$obj` resolves (via SSA) to `new C()`. */
  DataFlowCallable getInvokeCallee() {
    exists(
      VariableAccess fnvar, VariableAccess w, AssignExpr a, NewExpr nw, ClassLike cls,
      Ssa::LocalVariable v, Ssa::Definition def, Ssa::Cfg::BasicBlock bbw, int iw,
      Ssa::Cfg::BasicBlock bbr, int ir
    |
      c.(Php::FunctionCallExpression).getFunction() = fnvar and
      Ssa::variableAccessAt(bbr, ir, fnvar) and
      Ssa::Impl::ssaDefReachesRead(v, def, bbr, ir) and
      def.definesAt(v, bbw, iw) and
      Ssa::variableAccessAt(bbw, iw, w) and
      a.getLhs() = w and
      a.getRhs() = nw and
      cls.getName() = nw.getClassName() and
      result = cls.getAMethod() and
      result.(Method).getName() = "__invoke"
    )
  }

  int totalorder() { none() }
}

/** Gets the callable that node `n` belongs to. */
DataFlowCallable nodeGetEnclosingCallable(Node n) {
  result = n.getCfgNode().getScope()
  or
  result = n.(ThisParameterNode).getMethod()
  or
  result = n.(PostUpdateNode).getPreUpdateNode().getCfgNode().getScope()
}

/** Gets the data-flow type of node `n` (PHP is dynamically typed, so a single unknown type). */
DataFlowType getNodeType(Node n) { result = TUnknownType() and exists(n) }

predicate isParameterNode(ParameterNode p, DataFlowCallable c, ParameterPosition pos) {
  p.isParameterOf(c, pos)
}

predicate isArgumentNode(ArgumentNode n, DataFlowCall call, ArgumentPosition pos) {
  n.argumentOf(call, pos)
}

/**
 * Gets a viable target of `call`. A method call whose receiver class is inferred resolves precisely
 * to that class's method (type-based dispatch); otherwise resolution falls back to matching by name
 * (recall-first). Functions and static calls always resolve by name.
 */
DataFlowCallable viableCallable(DataFlowCall call) {
  // Precise: type-based instance-method dispatch.
  result = call.getTypedCallee()
  or
  // Precise: type-based static-method dispatch (`C::m`, `self::`, `static::`, `parent::`).
  result = call.getStaticTypedCallee()
  or
  // Fallback by name — for functions, and for calls where TYPE-based dispatch resolved no callee
  // (unknown receiver class, OR a class that lacks a matching method: trait/mixin/`__call`, or an
  // under-approximated type). Gating on "no typed callee was found" (not merely "no type was inferred")
  // keeps this recall-first — an inferred-but-methodless receiver must not silently drop the edge (B.4).
  call.getName() = result.getName() and
  not exists(call.getTypedCallee()) and
  not exists(call.getStaticTypedCallee())
  or
  result = call.getInlineCallee()
  or
  result = call.getInvokeCallee()
  or
  result = call.getStringNamedCallee()
  or
  result = call.getConstructCallee()
}

// --- Returns ------------------------------------------------------------------------------------

newtype TReturnKind = TNormalReturn()

abstract class ReturnKind extends TReturnKind {
  abstract string toString();
}

class NormalReturn extends ReturnKind, TNormalReturn {
  override string toString() { result = "return" }
}

/** A node holding a value returned from a callable. */
class ReturnNode extends Node {
  ReturnNode() {
    exists(Php::ReturnStatement r | this.(ExprNode).asExpr() = r.getChild())
    or
    // A `throw X` propagates the thrown value out of the callable (an exceptional "return"): the engine
    // carries it to the call's result node, from where `definitionReachingValue` routes it into a `catch`
    // binding whose `try` calls this function — the interprocedural exceptional path.
    exists(Php::ThrowExpression t | this.(ExprNode).asExpr() = t.getChild())
    or
    // An arrow function `fn(...) => expr` has no `return` statement — its body expression IS the
    // returned value. Its enclosing CFG scope is the `ArrowFunctionScope`, so this return connects to
    // the arrow's invocations (direct call, stored-then-called, array_map, …) like any other callable.
    this.(ExprNode).asExpr() = any(Php::ArrowFunction a).getBody()
    or
    // A constructor "returns" the mutated `$this` as the `new C(...)` value: the post-update of a
    // `$this` store base in the ctor body carries a `$this->f = v` field write out to the constructed
    // object, so `$o = new C($v); $o->f` flows generically (a `new` has no receiver argument, so this
    // is the ctor analogue of the receiver post-update used for ordinary method calls).
    exists(Php::MethodDeclaration ctor |
      ctor.getName().getValue() = "__construct" and
      this.(PostUpdateNode).getPreUpdateNode().asExpr() = thisAccess(ctor)
    )
  }

  ReturnKind getKind() { result = TNormalReturn() }
}

/** A node that receives the value returned by a call (the call expression itself). */
class OutNode extends ExprNode {
  OutNode() { this.getCfgNode() instanceof DataFlowCall }

  DataFlowCall getCall(ReturnKind kind) { result = this.getCfgNode() and exists(kind) }
}

OutNode getAnOutNode(DataFlowCall call, ReturnKind kind) { call = result.getCall(kind) }

// --- Node classification ------------------------------------------------------------------------

predicate nodeIsHidden(Node node) { none() }

class DataFlowExpr = Cfg::CfgNode;

class CastNode extends Node {
  CastNode() { none() }
}

/**
 * The synthetic `$this` parameter of a method (parameter position -1). Its value is the receiver of
 * each call to the method; a local-flow step connects it to every `$this` access in the body, so
 * `$this->f` stores/reads participate in the generic field-content model.
 */
class ThisParameterNode extends Node, TThisParameterNode {
  Php::MethodDeclaration m;

  ThisParameterNode() { this = TThisParameterNode(m) }

  /** Gets the method this is the `$this` parameter of. */
  Php::MethodDeclaration getMethod() { result = m }

  override string toString() { result = "$this in " + m.getName().getValue() }

  override Location getLocation() { result = m.getLocation() }
}

/**
 * A node representing the state of a value AFTER a call/store may have mutated it. `getPreUpdateNode`
 * is the node holding the value BEFORE. Field stores target the post-update of the base object, and
 * the engine reverses value-preserving steps to carry a callee's field write back to the caller.
 */
class PostUpdateNode extends Node, TExprPostUpdateNode {
  Cfg::CfgNode n;

  PostUpdateNode() { this = TExprPostUpdateNode(n) }

  /** Gets the node holding this value before the update. */
  Node getPreUpdateNode() { result = TExprNode(n) }

  override string toString() { result = "[post] " + n.toString() }

  override Location getLocation() { result = n.getLocation() }
}

// --- Types (trivial: PHP is dynamically typed) --------------------------------------------------

private newtype TDataFlowType = TUnknownType()

class DataFlowType extends TDataFlowType {
  string toString() { result = "" }
}

predicate compatibleTypes(DataFlowType t1, DataFlowType t2) { any() }

predicate typeStrongerThan(DataFlowType t1, DataFlowType t2) { none() }

// --- Content (array elements and object fields) -------------------------------------------------

newtype TContent =
  TArrayContent() or
  TFieldContent(string name) { name = any(Php::MemberAccessExpression m).getName().(Php::Name).getValue() }

class Content extends TContent {
  string toString() {
    this = TArrayContent() and result = "[]"
    or
    exists(string n | this = TFieldContent(n) and result = "." + n)
  }
}

predicate forceHighPrecision(Content c) { none() }

/**
 * A coarse approximation of `Content`, used by the shared engine's early (over-approximate) flow stages
 * to prune the search cheaply before the precise stage. Field contents are bucketed by their name's
 * first character (thousands of distinct field names collapse to a few dozen buckets), which keeps the
 * coarse stages fast on field-heavy object-oriented code while the precise `Content` recovers accuracy.
 */
private newtype TContentApprox =
  TArrayContentApprox() or
  TFieldContentApprox(string prefix) { prefix = fieldNamePrefix(_) }

/** Gets the one-character bucket of a field name (the approximation key). */
private string fieldNamePrefix(string name) {
  name = any(Php::MemberAccessExpression m).getName().(Php::Name).getValue() and
  result = name.prefix(1)
}

class ContentApprox extends TContentApprox {
  string toString() {
    this = TArrayContentApprox() and result = "[]"
    or
    exists(string p | this = TFieldContentApprox(p) and result = "." + p + "*")
  }
}

ContentApprox getContentApprox(Content c) {
  c = TArrayContent() and result = TArrayContentApprox()
  or
  exists(string n | c = TFieldContent(n) and result = TFieldContentApprox(n.prefix(1)))
}

// --- Positions ----------------------------------------------------------------------------------

class ParameterPosition extends int {
  ParameterPosition() { this = [-1 .. 63] }
}

class ArgumentPosition extends int {
  ArgumentPosition() { this = [-1 .. 63] }
}

// Position -1 is the `this`/receiver position; it matches itself like every other position.
predicate parameterMatch(ParameterPosition ppos, ArgumentPosition apos) { ppos = apos }

// --- Local flow ---------------------------------------------------------------------------------

/** Holds if `target` is assigned the value of `rhs` (plain, augmented or reference assignment). */
private predicate simpleAssignment(VariableAccess target, Expr rhs) {
  exists(AssignExpr a | a.getLhs() = target and a.getRhs() = rhs)
  or
  // `$x .= v` carries the value of the whole augmented expression (a read-modify-write combining the
  // old `$x` and `v`), not just `v` — so taint on the old value propagates via `structuralPropagator`
  // over the augmented expression into the new definition of `$x` (AUDIT.md A.2).
  exists(Php::AugmentedAssignmentExpression a | a.getLeft() = target and rhs = a)
  or
  exists(Php::ReferenceAssignmentExpression a | a.getLeft() = target and a.getRight() = rhs)
  or
  // Nested element/property update at any depth (`$o->a[2]->b = v`) re-defines the root variable.
  exists(AssignExpr a |
    Ssa::isNestedAccess(a.getLhs()) and target = Ssa::rootVariableOfAccess(a.getLhs()) and rhs = a.getRhs()
  )
}

/**
 * Gets the expression whose value an SSA definition `def` carries: the right-hand side for an
 * assignment (`$x = rhs`), or the binding node itself for a parameter, `foreach` value, `catch`
 * variable, etc.
 */
private Expr definitionValue(Ssa::Definition def) {
  exists(VariableAccess w, Ssa::LocalVariable v, Ssa::Cfg::BasicBlock bbw, int iw |
    def.definesAt(v, bbw, iw) and Ssa::variableAccessAt(bbw, iw, w)
  |
    simpleAssignment(w, result)
    or
    not simpleAssignment(w, _) and result = w
  )
}

/**
 * Gets a value that flows out of SSA definition `def`. For a normal definition this is its assigned
 * value; for a phi node — which has no syntactic value — it is, recursively, a value flowing into any
 * of the phi's inputs (`phiHasInputFromBlock`). Without this, taint DROPS at a branch join: a phi
 * `reaches` the read but `definitionValue(phi)` is empty, so the tainted branch's value never crosses
 * the join. This is a no-op on the linearised CFG (no join ⇒ no phi) and is what lets taint traverse
 * the SSA φ once the CFG branches (`if`/`else`/loops).
 */
private Expr definitionReachingValue(Ssa::Definition def) {
  result = definitionValue(def)
  or
  exists(Ssa::Definition inp |
    Ssa::Impl::phiHasInputFromBlock(def, inp, _) and result = definitionReachingValue(inp)
  )
  or
  // A weak (uncertain) write — a partial update `$x[k]=v` / `$x->p=v` — does not overwrite the whole
  // variable: the prior definition's value may still be present, so it also reaches. Following this
  // input is what lets taint survive an unrelated element/property assignment (AUDIT.md A.1).
  exists(Ssa::Definition inp |
    Ssa::Impl::uncertainWriteDefinitionInput(def, inp) and result = definitionReachingValue(inp)
  )
  or
  // Try/catch modelled as a branch (like `if`/`else`): the `catch (E $e)` binding — now a real SSA
  // definition (see `CatchVarLeaf` in the CFG) — is assigned what the `try` throws. That is either a
  // direct `throw X` in the try body (X is the value), or the result of a call that can throw (`throw` is
  // a ReturnNode, so the thrown value reaches the call result). The SSA local-flow then carries it to
  // every `$e` read. Recall-first (any throw in the try / a called function reaches the catch).
  exists(
    VariableAccess w, Ssa::LocalVariable v, Ssa::Cfg::BasicBlock bbw, int iw, Php::CatchClause cat,
    Php::TryStatement try
  |
    def.definesAt(v, bbw, iw) and
    Ssa::variableAccessAt(bbw, iw, w) and
    w = cat.getName() and
    cat = try.getChild(_)
  |
    // a direct `throw X` in the try body — the thrown value
    exists(Php::ThrowExpression thr |
      thr.(Php::AstNode).getParent+() = try.getBody() and result = thr.getChild()
    )
    or
    // a call in the try that can throw — the thrown value is on its result node (ReturnNode)
    exists(Php::FunctionCallExpression call, Php::FunctionDefinition callee |
      call.(Php::AstNode).getParent+() = try.getBody() and
      callee.getName().getValue() = call.getFunction().(Php::Name).getValue() and
      exists(Php::ThrowExpression thr | thr.(Php::AstNode).getParent+() = callee.getBody()) and
      result = call
    )
  )
}

/** Value-preserving local step: an SSA definition's value flows to every read it reaches. */
predicate simpleLocalFlowStep(Node node1, Node node2, string model) {
  model = "" and
  exists(
    Ssa::LocalVariable v, Ssa::Definition def, Ssa::Cfg::BasicBlock bbr, int ir, VariableAccess read
  |
    node1.asExpr() = definitionReachingValue(def) and
    Ssa::Impl::ssaDefReachesRead(v, def, bbr, ir) and
    Ssa::variableAccessAt(bbr, ir, read) and
    node2.asExpr() = read
  )
  or
  // The synthetic `$this` parameter flows to every `$this` access in the method body ($this has no SSA
  // definition of its own — it is an implicit variable — so this replaces the missing entry-def edge).
  model = "" and
  exists(Php::MethodDeclaration m |
    node1 = TThisParameterNode(m) and node2.asExpr() = thisAccess(m)
  )
  or
  // `clone $x` copies the object's fields, so field taint on the source carries to the clone
  // (value-preserving — content/fields flow, `$b = clone $a; $b->f` observes `$a->f`).
  model = "" and
  node1.asExpr() = node2.asExpr().(Php::CloneExpression).getChild()
  or
  // Caller-side leg of interprocedural field mutation: the POST-UPDATE of a variable read (an argument /
  // receiver / store base whose object a callee may have mutated) flows to a LATER read of the same SSA
  // variable, so `fill($o); … $o->f` observes a mutation `fill` made to `$o`. CFG-ordered so a
  // post-update never flows to an EARLIER read (that would be an unsound backward edge).
  model = "" and
  exists(
    Ssa::LocalVariable v, Ssa::Definition def, Ssa::Cfg::BasicBlock bb1, int i1, VariableAccess r1,
    Ssa::Cfg::BasicBlock bb2, int i2, VariableAccess r2
  |
    // Drive from the small set of post-update pre-nodes (call arguments / store bases), NOT from every
    // read pair — keeps this step from becoming quadratic in a variable's reads on large code bases.
    node1.(PostUpdateNode).getPreUpdateNode().asExpr() = r1 and
    Ssa::variableAccessAt(bb1, i1, r1) and
    Ssa::Impl::ssaDefReachesRead(v, def, bb1, i1) and
    Ssa::Impl::ssaDefReachesRead(v, def, bb2, i2) and
    Ssa::variableAccessAt(bb2, i2, r2) and
    r1 != r2 and
    // CFG order: r1 strictly before r2 (same block earlier index, or an earlier block).
    (bb1 = bb2 and i1 < i2 or bb1.getASuccessor+() = bb2) and
    node2.asExpr() = r2
  )
}

predicate localFlowStep(Node node1, Node node2) { simpleLocalFlowStep(node1, node2, _) }

/** Gets the constant string key of a `$GLOBALS['k']` subscript. */
private string globalsKey(Php::SubscriptExpression sub) {
  sub.getChild(0).(VariableAccess).getName() = "GLOBALS" and
  result = sub.getChild(1).(Php::String).getChild(_).(Php::StringContent).getValue()
}

/** Gets a function/method/closure body AST node. */
private AstNode aCallableBody() {
  result = any(Php::FunctionDefinition f).getBody() or
  result = any(Php::MethodDeclaration m).getBody() or
  result = any(Php::AnonymousFunction a).getBody() or
  result = any(Php::ArrowFunction a).getBody()
}

/** Holds if `v` sits at file top level (outside any function/method/closure body). */
private predicate atTopLevel(VariableAccess v) { not v.(Php::AstNode).getParent+() = aCallableBody() }

/** Holds if `v` (named `name`) is inside a function/method that declares `global $name`. */
private predicate inFunctionGlobal(VariableAccess v, string name) {
  exists(Php::GlobalDeclaration g, AstNode body |
    body = aCallableBody() and
    g.getChild(_).(VariableAccess).getName() = name and
    g.(Php::AstNode).getParent+() = body and
    v.(Php::AstNode).getParent+() = body
  )
}

/**
 * Holds if variable access `v` (named `name`) refers to the GLOBAL `$name`: either it sits at file
 * top level (where `$name` is the global) or it is inside a function that declares `global $name`.
 */
private predicate inGlobalScope(VariableAccess v, string name) {
  v.getName() = name and (atTopLevel(v) or inFunctionGlobal(v, name))
}

predicate jumpStep(Node node1, Node node2) {
  // Global variables (`global $g`) alias a single cross-scope value: assigning `$g` in one scope
  // flows to reads of `$g` in another. Modelled as a jump step (non-local, value-preserving), so it
  // works for every data-flow query and is not restricted to a single file. Both the writing and the
  // reading scope must actually declare `global $g` — otherwise a purely local `$g` in a function that
  // never touches the global would be cross-linked to every other `$g` in the program (a false positive).
  exists(string gname, AssignExpr a, VariableAccess w, VariableAccess r |
    a.getLhs() = w and
    w.getName() = gname and
    r.getName() = gname and
    r != w and
    inGlobalScope(w, gname) and
    inGlobalScope(r, gname) and
    // At least one endpoint must be a function's `global $g` import — a pure top-level `$g → $g` flow is
    // ordinary local dataflow, not a cross-scope global alias, so it must NOT get a (SSA-order-blind)
    // jump step (that would cross-link every same-named top-level variable — a false positive).
    (inFunctionGlobal(w, gname) or inFunctionGlobal(r, gname)) and
    node1.asExpr() = a.getRhs() and
    node2.asExpr() = r
  )
  or
  // The `$GLOBALS['k']` superglobal is a genuine global: assigning a key in one scope/file flows to
  // reads of the same key anywhere. A jump step (cross-file), unlike a scope-local `=&` alias. (B.6)
  exists(AssignExpr a, Php::SubscriptExpression w, Php::SubscriptExpression r, string key |
    a.getLhs() = w and
    key = globalsKey(w) and
    key = globalsKey(r) and
    w != r and
    node1.asExpr() = a.getRhs() and
    node2.asExpr() = r
  )
  or
  // A `static $s` local persists BETWEEN calls: assigning `$s = X` in one invocation flows to reads of
  // `$s` in a later one. Modelled as a jump step (SSA-order-blind, like a global), scoped to the single
  // function that declares the `static` — so it is not cross-linked to unrelated same-named locals.
  exists(
    Php::StaticVariableDeclaration sd, string sname, AssignExpr a, VariableAccess w, VariableAccess r,
    AstNode fn
  |
    (
      fn instanceof Php::FunctionDefinition or
      fn instanceof Php::MethodDeclaration or
      fn instanceof Php::AnonymousFunction
    ) and
    sd.(Php::AstNode).getParent+() = fn and
    sname = sd.getName().(Php::VariableName).getChild().getValue() and
    a.getLhs() = w and
    w.getName() = sname and
    w.(Php::AstNode).getParent+() = fn and
    r.getName() = sname and
    r.(Php::AstNode).getParent+() = fn and
    r != w and
    node1.asExpr() = a.getRhs() and
    node2.asExpr() = r
  )
}

// --- Content steps ------------------------------------------------------------------------------

/** Reading an array element (`$a[..]`) or object field (`$o->f`). */
predicate readStep(Node node1, ContentSet c, Node node2) {
  exists(Php::SubscriptExpression sub |
    node1.asExpr() = sub.getChild(0) and node2.asExpr() = sub and c = TArrayContent()
  )
  or
  exists(Php::MemberAccessExpression m, string f |
    node1.asExpr() = m.getObject() and
    node2.asExpr() = m and
    f = m.getName().(Php::Name).getValue() and
    c = TFieldContent(f)
  )
}

/** Storing into an array element (`$a[..] = v`), a field (`$o->f = v`), or an array literal. */
predicate storeStep(Node node1, ContentSet c, Node node2) {
  // `$a[k] = v` — stores into the base variable, which is an SSA update definition and therefore
  // flows to subsequent reads of `$a`.
  exists(AssignExpr a, Php::SubscriptExpression sub |
    a.getLhs() = sub and node1.asExpr() = a.getRhs() and
    node2.(PostUpdateNode).getPreUpdateNode().asExpr() = sub.getChild(0) and
    c = TArrayContent()
  )
  or
  // `$o->f = v` — stores `v` into field `f` of the base object's POST-UPDATE node, so the mutation is
  // observed at later reads of `$o` (and, interprocedurally, carried back through the receiver).
  exists(AssignExpr a, Php::MemberAccessExpression m, string f |
    a.getLhs() = m and
    node1.asExpr() = a.getRhs() and
    node2.(PostUpdateNode).getPreUpdateNode().asExpr() = m.getObject() and
    f = m.getName().(Php::Name).getValue() and
    c = TFieldContent(f)
  )
  or
  // Array literal `[v, ...]` stores each element.
  exists(Php::ArrayElementInitializer el, Php::ArrayCreationExpression arr |
    el = arr.getChild(_) and node1.asExpr() = el.getChild(_) and node2.asExpr() = arr and
    c = TArrayContent()
  )
  or
  // Augmented store `$a[k] .= v` / `$a[k] += v` — the right operand flows into the base container's
  // element content (mirrors the plain `$a[k] = v` store; the base is redefined via updateBaseVariable).
  exists(Php::AugmentedAssignmentExpression a, Php::SubscriptExpression sub |
    a.getLeft() = sub and node1.asExpr() = a.getRight() and node2.asExpr() = sub.getChild(0) and
    c = TArrayContent()
  )
  or
  // Augmented store `$o->f .= v` — the right operand flows into the base object's post-update field.
  exists(Php::AugmentedAssignmentExpression a, Php::MemberAccessExpression m, string f |
    a.getLeft() = m and
    node1.asExpr() = a.getRight() and
    node2.(PostUpdateNode).getPreUpdateNode().asExpr() = m.getObject() and
    f = m.getName().(Php::Name).getValue() and
    c = TFieldContent(f)
  )
  or
  // Two-level fold: the post-update of a nested store base `$o->f` (holding the inner mutation from
  // `$o->f->g = v` or `$o->f[] = v`) is stored back onto `$o`'s post-update at field `f`, so the nested
  // mutation reaches later `$o->f` reads (and, interprocedurally, the receiver of a method that did it).
  exists(Php::MemberAccessExpression m, string f |
    m = nestedStoreBase() and
    node1.(PostUpdateNode).getPreUpdateNode().asExpr() = m and
    node2.(PostUpdateNode).getPreUpdateNode().asExpr() = m.getObject() and
    f = m.getName().(Php::Name).getValue() and
    c = TFieldContent(f)
  )
}

predicate clearsContent(Node n, ContentSet c) { none() }

predicate expectsContent(Node n, ContentSet c) { none() }

// --- Regions / reachability ---------------------------------------------------------------------

class NodeRegion instanceof Unit {
  string toString() { result = "NodeRegion" }

  predicate contains(Node n) { none() }

  int totalOrder() { result = 1 }
}

predicate isUnreachableInCall(NodeRegion nr, DataFlowCall call) { none() }

// --- Misc engine hooks --------------------------------------------------------------------------

predicate allowParameterReturnInSelf(ParameterNode p) { none() }

predicate localMustFlowStep(Node node1, Node node2) { localFlowStep(node1, node2) }

private newtype TLambdaCallKind = TNoLambda()

class LambdaCallKind = TLambdaCallKind;

/** Holds if function call `fc` is a first-class-callable creation `f(...)` (a `...` placeholder). */
private predicate isFirstClassCallable(FunctionCall fc) {
  exists(Php::VariadicPlaceholder p |
    p.(Php::AstNode).getParent+() = fc.(Php::FunctionCallExpression).getArguments()
  )
}

/** Holds if method call `mc` is a first-class-callable creation `$obj->m(...)` (a `...` placeholder). */
private predicate isFirstClassCallableMethod(MethodCall mc) {
  exists(Php::VariadicPlaceholder p | p.(Php::AstNode).getParent+() = mc)
}

/**
 * Holds if `creation` creates a first-class callable whose body is the callable `c`: a closure, an arrow
 * function, or the PHP-8.1 first-class-callable syntax `f(...)` (which references the function/method
 * `f`). The callable value flows (via ordinary data flow) to wherever it is invoked, where `lambdaCall`
 * picks it up — so a callable stored in a variable and called later is handled generally, without
 * enumerating higher-order built-ins (B.2).
 */
predicate lambdaCreation(Node creation, LambdaCallKind kind, DataFlowCallable c) {
  kind = TNoLambda() and
  (
    (creation.asExpr() instanceof Php::AnonymousFunction or creation.asExpr() instanceof Php::ArrowFunction) and
    c = creation.asExpr()
    or
    // First-class callable `wrap(...)`: the callable is the referenced function (by name).
    exists(FunctionCall fc | fc = creation.asExpr() and isFirstClassCallable(fc) and c.getName() = fc.getName())
    or
    // Method first-class callable `$obj->m(...)`: the callable is the resolved method (by inferred type,
    // falling back to name when the receiver type is unknown).
    exists(MethodCall mc |
      mc = creation.asExpr() and
      isFirstClassCallableMethod(mc) and
      (
        c = TI::inferredMethod(mc)
        or
        not TI::hasInferredReceiver(mc) and c.getName() = mc.getMethodName()
      )
    )
    or
    // `Closure::fromCallable('func')` — a closure for the referenced function (by name).
    exists(StaticMethodCall sc |
      sc = creation.asExpr() and
      sc.getTargetName() = "Closure" and
      sc.getMethodName() = "fromCallable" and
      c.getName() = sc.getArgument(0).(StringLiteral).getValue()
    )
    or
    // Array callable `[$obj, 'm']` / `['C', 'm']`: the callable is the resolved method. Stored in a
    // variable and invoked later (`$cb($x)`) — handled generally via `lambdaCall`.
    c = TI::arrayCallableMethod(creation.asExpr())
  )
}

/**
 * Holds if `call` invokes a value through `receiver`: a dynamic call `$cb(...)` where the callee is an
 * expression (a variable/field holding a closure), not a static function name. The engine connects a
 * closure that flows to `receiver` with this call, mapping arguments to the closure's parameters and its
 * return to the call result.
 */
predicate lambdaCall(DataFlowCall call, LambdaCallKind kind, Node receiver) {
  kind = TNoLambda() and
  exists(FunctionCall fc |
    fc = call.getCall() and
    fc.isDynamic() and
    receiver.asExpr() = fc.(Php::FunctionCallExpression).getFunction()
  )
}

predicate additionalLambdaFlowStep(Node nodeFrom, Node nodeTo, boolean preservesValue) { none() }

predicate knownSourceModel(Node source, string model) { none() }

predicate knownSinkModel(Node sink, string model) { none() }

predicate neverSkipInPathGraph(Node node) { none() }
