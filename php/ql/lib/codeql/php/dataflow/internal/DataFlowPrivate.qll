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

newtype TNode = TExprNode(Cfg::CfgNode n)

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

  string toString() { result = super.toString() }

  Location getLocation() { result = super.getLocation() }

  /** Gets the callee name (function or method name). */
  string getName() {
    result = c.(FunctionCall).getName() or
    result = c.(MethodCall).getMethodName() or
    result = c.(StaticMethodCall).getMethodName()
  }

  DataFlowCallable getEnclosingCallable() { result = super.getScope() }

  /** Gets the CFG node of this call's `pos`th argument. */
  Cfg::CfgNode getArgumentCfgNode(int pos) {
    result.getAstNode() = c.getArgument(pos) and
    // Named arguments (`f(x: $v)`) are routed by name via a taint step, so exclude them here to avoid
    // mis-mapping to the parameter at their textual position.
    not exists(Php::Argument a |
      a.getChild() = c.getArgument(pos) and exists(a.getName().(Php::Name))
    )
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
DataFlowCallable nodeGetEnclosingCallable(Node n) { result = n.getCfgNode().getScope() }

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
class ReturnNode extends ExprNode {
  ReturnNode() { exists(Php::ReturnStatement r | this.asExpr() = r.getChild()) }

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

class PostUpdateNode extends Node {
  PostUpdateNode() { none() }

  Node getPreUpdateNode() { none() }
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

class ContentApprox = Content;

ContentApprox getContentApprox(Content c) { result = c }

// --- Positions ----------------------------------------------------------------------------------

class ParameterPosition extends int {
  ParameterPosition() { this = [0 .. 63] }
}

class ArgumentPosition extends int {
  ArgumentPosition() { this = [0 .. 63] }
}

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
}

predicate localFlowStep(Node node1, Node node2) { simpleLocalFlowStep(node1, node2, _) }

predicate jumpStep(Node node1, Node node2) {
  // Global variables (`global $g`) alias a single cross-scope value: assigning `$g` in one scope
  // flows to reads of `$g` in another. Modelled as a jump step (non-local, value-preserving), so it
  // works for every data-flow query and is not restricted to a single file.
  exists(string gname, AssignExpr a, VariableAccess w, VariableAccess r |
    gname = any(Php::GlobalDeclaration g).getChild(_).(VariableAccess).getName() and
    a.getLhs() = w and
    w.getName() = gname and
    r.getName() = gname and
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
    a.getLhs() = sub and node1.asExpr() = a.getRhs() and node2.asExpr() = sub.getChild(0) and
    c = TArrayContent()
  )
  or
  // `$o->f = v` — stores into the base object at field `f`.
  exists(AssignExpr a, Php::MemberAccessExpression m, string f |
    a.getLhs() = m and
    node1.asExpr() = a.getRhs() and
    node2.asExpr() = m.getObject() and
    f = m.getName().(Php::Name).getValue() and
    c = TFieldContent(f)
  )
  or
  // Array literal `[v, ...]` stores each element.
  exists(Php::ArrayElementInitializer el, Php::ArrayCreationExpression arr |
    el = arr.getChild(_) and node1.asExpr() = el.getChild(_) and node2.asExpr() = arr and
    c = TArrayContent()
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

predicate lambdaCreation(Node creation, LambdaCallKind kind, DataFlowCallable c) { none() }

predicate lambdaCall(DataFlowCall call, LambdaCallKind kind, Node receiver) { none() }

predicate additionalLambdaFlowStep(Node nodeFrom, Node nodeTo, boolean preservesValue) { none() }

predicate knownSourceModel(Node source, string model) { none() }

predicate knownSinkModel(Node sink, string model) { none() }

predicate neverSkipInPathGraph(Node node) { none() }
