/**
 * Instantiation of the shared control-flow-graph library for PHP.
 *
 * v1 model: a connected, linearised CFG. Statements are visited in pre-order, expressions in
 * post-order (operands before the operation), and argument wrappers are traversed. Functions,
 * methods, closures and type declarations are scope boundaries: they appear as leaves in their
 * enclosing scope and (for callables) get their own control-flow graph.
 *
 * Branching is modelled for `if`/`if-else` (`IfTree`/`IfElseTree`) and `while`/`do` loops
 * (`WhileTree`/`DoTree`, with a back-edge at the loop header). Still linearised (see AUDIT.md §3,
 * Phase A): `for`/`foreach`, `switch`/`match`, short-circuit `&&`/`||`/`??`, and the abnormal
 * completions `break`/`continue`/`return`/`throw` (+ `try`/`catch`/`finally`).
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.controlflow.Cfg as CfgShared
private import codeql.Locations

module Completion {
  import codeql.controlflow.SuccessorType

  private newtype TCompletion =
    TSimpleCompletion() or
    TBooleanCompletion(boolean b) { b in [false, true] } or
    TReturnCompletion() or
    TBreakCompletion() or
    TContinueCompletion() or
    TRaiseCompletion()

  abstract class Completion extends TCompletion {
    abstract string toString();

    predicate isValidForSpecific(AstNode e) { none() }

    predicate isValidFor(AstNode e) { this.isValidForSpecific(e) }

    abstract SuccessorType getAMatchingSuccessorType();
  }

  abstract class NormalCompletion extends Completion { }

  class SimpleCompletion extends NormalCompletion, TSimpleCompletion {
    override string toString() { result = "SimpleCompletion" }

    override predicate isValidFor(AstNode e) { not any(Completion c).isValidForSpecific(e) }

    override DirectSuccessor getAMatchingSuccessorType() { any() }
  }

  class BooleanCompletion extends NormalCompletion, TBooleanCompletion {
    boolean value;

    BooleanCompletion() { this = TBooleanCompletion(value) }

    override string toString() { result = "BooleanCompletion(" + value + ")" }

    /**
     * The condition of an `if` that has an `else`/`elseif` completes with BOTH boolean values (a
     * non-deterministic branch — sound over-approximation without condition splitting), consumed by
     * `IfElseTree` to route to the `then` (true) / `else` (false) bodies as genuine CFG alternatives.
     */
    override predicate isValidForSpecific(AstNode e) {
      exists(Php::IfStatement s |
        e = s.(Php::AstNode).getAFieldOrChild() and
        e instanceof Php::ParenthesizedExpression and
        exists(AstNode ec |
          ec = s.(Php::AstNode).getAFieldOrChild() and
          (ec instanceof Php::ElseClause or ec instanceof Php::ElseIfClause)
        )
      )
      or
      e = any(Php::WhileStatement w).getCondition()
      or
      e = any(Php::DoStatement d).getCondition()
      or
      e = any(Php::ForStatement f).getCondition()
      or
      // The left operand of a short-circuit `&&`/`||` (and their low-precedence `and`/`or` forms)
      // completes true/false, routing to the right operand (evaluated) or the result (short-circuit).
      exists(Php::BinaryExpression b | b.getOperator() = ["&&", "||", "and", "or"] and e = b.getLeft())
      or
      // The condition of a ternary `c ? a : b` (or elvis `c ?: b`) routes to the chosen branch.
      e = any(Php::ConditionalExpression ce).getCondition()
    }

    override BooleanSuccessor getAMatchingSuccessorType() { result.getValue() = value }

    final boolean getValue() { result = value }
  }

  /**
   * An abnormal completion that transfers control out of the normal sequential flow: `return`,
   * `break`, `continue`, or `throw`. Being non-normal, it is propagated upwards by `last(...)` through
   * every enclosing tree whose `propagatesAbnormal` holds, until a construct consumes it (a loop/switch
   * for break/continue, a `try`/callable scope for raise/return).
   */
  abstract class AbnormalCompletion extends Completion { }

  class ReturnCompletion extends AbnormalCompletion, TReturnCompletion {
    override string toString() { result = "ReturnCompletion" }

    override predicate isValidForSpecific(AstNode e) { e instanceof Php::ReturnStatement }

    override ReturnSuccessor getAMatchingSuccessorType() { any() }
  }

  class BreakCompletion extends AbnormalCompletion, TBreakCompletion {
    override string toString() { result = "BreakCompletion" }

    override predicate isValidForSpecific(AstNode e) { e instanceof Php::BreakStatement }

    override BreakSuccessor getAMatchingSuccessorType() { any() }
  }

  class ContinueCompletion extends AbnormalCompletion, TContinueCompletion {
    override string toString() { result = "ContinueCompletion" }

    override predicate isValidForSpecific(AstNode e) { e instanceof Php::ContinueStatement }

    override ContinueSuccessor getAMatchingSuccessorType() { any() }
  }

  class RaiseCompletion extends AbnormalCompletion, TRaiseCompletion {
    override string toString() { result = "RaiseCompletion" }

    override predicate isValidForSpecific(AstNode e) { e instanceof Php::ThrowExpression }

    override ExceptionSuccessor getAMatchingSuccessorType() { any() }
  }
}

module CfgScope {
  /** A scope that gets its own control-flow graph: a callable body, or the file top level. */
  abstract class CfgScope extends AstNode { }

  class TopLevelScope extends CfgScope instanceof Php::Program { }

  class FunctionScope extends CfgScope instanceof Php::FunctionDefinition { }

  class MethodScope extends CfgScope instanceof Php::MethodDeclaration { }

  class AnonFunctionScope extends CfgScope instanceof Php::AnonymousFunction { }

  class ArrowFunctionScope extends CfgScope instanceof Php::ArrowFunction { }
}

private import Completion
private import CfgScope

private module Implementation implements CfgShared::InputSig<Location> {
  import codeql.php.AST
  import Completion
  import CfgScope

  predicate completionIsNormal(Completion c) { c instanceof NormalCompletion }

  predicate completionIsSimple(Completion c) { c instanceof SimpleCompletion }

  predicate completionIsValidFor(Completion c, AstNode e) { c.isValidFor(e) }

  // Not using CFG splitting: dummy types.
  private newtype TUnit = Unit()

  additional class SplitKindBase = TUnit;

  additional class Split extends TUnit {
    string toString() { none() }
  }

  additional int maxSplits() { result = 0 }

  /** Gets the innermost CFG scope enclosing `n`. */
  CfgScope getCfgScope(AstNode n) {
    exists(AstNode p | p = n.getParent() |
      result = p
      or
      not p instanceof CfgScope and result = getCfgScope(p)
    )
  }

  predicate scopeFirst(CfgScope scope, AstNode e) {
    scope instanceof Php::Program and first(scope, e)
    or
    first(callableBodyChild(scope, 0), e)
  }

  predicate scopeLast(CfgScope scope, AstNode e, Completion c) {
    scope instanceof Php::Program and last(scope, e, c)
    or
    exists(int i |
      last(callableBodyChild(scope, i), e, c) and not exists(callableBodyChild(scope, i + 1))
    )
  }

  SuccessorType getAMatchingSuccessorType(Completion c) { result = c.getAMatchingSuccessorType() }

  int idOfAstNode(AstNode node) { none() }

  int idOfCfgScope(CfgScope scope) { none() }
}

module CfgImpl = CfgShared::Make<Location, Implementation>;

private import CfgImpl

/** Holds if `n` is a callable (function, method, closure or arrow function). */
private predicate isCallable(AstNode n) {
  n instanceof Php::FunctionDefinition or
  n instanceof Php::MethodDeclaration or
  n instanceof Php::AnonymousFunction or
  n instanceof Php::ArrowFunction
}

/** Holds if `n` is a type declaration, which is a leaf in its enclosing scope's CFG. */
private predicate isTypeDeclaration(AstNode n) {
  n instanceof Php::ClassDeclaration or
  n instanceof Php::InterfaceDeclaration or
  n instanceof Php::TraitDeclaration or
  n instanceof Php::EnumDeclaration
}

/** Gets the formal-parameters node of callable `c`, if any. */
private Php::FormalParameters formalParametersOf(AstNode c) {
  result = c.(Php::FunctionDefinition).getParameters() or
  result = c.(Php::MethodDeclaration).getParameters() or
  result = c.(Php::AnonymousFunction).getParameters() or
  result = c.(Php::ArrowFunction).getParameters()
}

/** Gets the body of callable `c`. */
private AstNode callableBody(AstNode c) {
  result = c.(Php::FunctionDefinition).getBody() or
  result = c.(Php::MethodDeclaration).getBody() or
  result = c.(Php::AnonymousFunction).getBody() or
  result = c.(Php::ArrowFunction).getBody()
}

/**
 * Gets the `i`th body-child of callable `c`: its parameters in order (0-based), followed by its
 * body. This is what the callable's own CFG scope flows through, so parameters (and their default
 * values) are part of the graph.
 */
AstNode callableBodyChild(AstNode c, int i) {
  result = rank[i + 1](AstNode child, int j |
      child = formalParametersOf(c).getChild(j) and j >= 0
      or
      child = callableBody(c) and j = 1000000
    |
      child order by j
    )
}

/** Gets the `i`th CFG-relevant child of `parent`, ordered by source position. */
private AstNode rankedCfgChild(AstNode parent, int i) {
  result =
    rank[i](AstNode child, Location l |
      child = parent.(Php::AstNode).getAFieldOrChild() and
      child instanceof ControlFlowTree and
      l = child.getLocation()
    |
      child order by l.getStartLine(), l.getStartColumn(), l.getEndLine(), l.getEndColumn(), child.toString()
    )
}

/** The file top level, visited in pre-order over its statements. */
private class ProgramTree extends StandardPreOrderTree instanceof Php::Program {
  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }
}

/**
 * A structural (non-expression) node, visited in pre-order over its CFG-relevant children.
 *
 * This covers statements, blocks and every intermediate wrapper (`switch_block`, `case_statement`,
 * `arguments`, `argument`, `else_clause`, …), which keeps the graph connected through arbitrary
 * nesting. Childless structural nodes are excluded (they act as leaf tokens with no flow).
 */
private class StructuralTree extends StandardPreOrderTree instanceof Php::AstNode {
  StructuralTree() {
    not this instanceof Php::Expression and
    not this instanceof Php::Program and
    not this instanceof Php::Token and
    not this instanceof Php::IfStatement and
    not this instanceof Php::WhileStatement and
    not this instanceof Php::DoStatement and
    not this instanceof Php::ForStatement and
    not this instanceof Php::ForeachStatement and
    // The `match` block is not a CFG node: `MatchTree` routes the subject directly to the arms, so the
    // block must not also linearise them here.
    not this instanceof Php::MatchBlock and
    // Abnormal-completion producers and the constructs that consume them get dedicated trees.
    not this instanceof Php::BreakStatement and
    not this instanceof Php::ContinueStatement and
    not this instanceof Php::ReturnStatement and
    not this instanceof Php::SwitchStatement and
    not this instanceof Php::SwitchBlock and
    not this instanceof Php::TryStatement and
    not isCallable(this) and
    not isTypeDeclaration(this)
  }

  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }
}
// NOTE: these read the RAW AST (`getAFieldOrChild`), NOT `rankedCfgChild` — because `ifHasElse`
// gates the `IfTree`/`IfElseTree` characteristic predicates, and `rankedCfgChild` filters by
// `instanceof ControlFlowTree`, which would make those char-preds non-monotonically recursive.
/** Gets the condition sub-expression of `if` node `n` (its parenthesized child). */
private AstNode ifConditionOf(Php::IfStatement n) {
  result = n.(Php::AstNode).getAFieldOrChild() and result instanceof Php::ParenthesizedExpression
}

/** Gets the `else`/`elseif` clause of `if` node `n`. */
private AstNode ifElseClauseOf(Php::IfStatement n) {
  result = n.(Php::AstNode).getAFieldOrChild() and
  (result instanceof Php::ElseClause or result instanceof Php::ElseIfClause)
}

/** Gets the then-body of `if` node `n` (its child that is neither condition, else, nor a token). */
private AstNode ifThenBodyOf(Php::IfStatement n) {
  result = n.(Php::AstNode).getAFieldOrChild() and
  not result instanceof Php::ParenthesizedExpression and
  not result instanceof Php::ElseClause and
  not result instanceof Php::ElseIfClause and
  not result instanceof Php::Token
}

/** Holds if `if` node `n` has an `else`/`elseif` clause. */
private predicate ifHasElse(Php::IfStatement n) { exists(ifElseClauseOf(n)) }

/**
 * An `if` WITHOUT `else`: the condition is an extra `last` (fall-through), giving the post-`if` join
 * two predecessors ({body-writes, pre-if}) ⇒ a real SSA φ. Taint crosses it thanks to
 * `definitionReachingValue` (phi-input flow) in `DataFlowPrivate`.
 */
private class IfTree extends StandardPreOrderTree instanceof Php::IfStatement {
  IfTree() { not ifHasElse(this) }

  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }

  override predicate last(AstNode last, Completion c) {
    super.last(last, c)
    or
    last(ifConditionOf(this), last, c)
  }
}

/**
 * An `if` WITH `else`/`elseif`: a real branch (canonical pattern, cf. Ruby `ConditionalExprTree`).
 * `first` is the condition; it completes with a boolean routing to the then-body (true) or else
 * clause (false); both rejoin at the `if` (post-order) ⇒ a real SSA φ (`then ⊔ else`), NO
 * `then → else` leak. Taint crosses the φ via `definitionReachingValue` (phi-input flow).
 */
private class IfElseTree extends PostOrderTree instanceof Php::IfStatement {
  IfElseTree() { ifHasElse(this) }

  // Abnormal completions (break/continue/return/throw) from either branch propagate to the enclosing
  // loop/switch/try/callable; only NORMAL branch completions rejoin at the `if` node.
  final override predicate propagatesAbnormal(AstNode child) {
    child = ifThenBodyOf(this) or child = ifElseClauseOf(this)
  }

  final override predicate first(AstNode f) { first(ifConditionOf(this), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(boolean b | last(ifConditionOf(this), pred, c) and b = c.(BooleanCompletion).getValue() |
      b = true and first(ifThenBodyOf(this), succ)
      or
      b = false and first(ifElseClauseOf(this), succ)
    )
    or
    (last(ifThenBodyOf(this), pred, c) or last(ifElseClauseOf(this), pred, c)) and
    succ = this and
    c instanceof NormalCompletion
  }
}

/**
 * Holds if a `return`/`throw` occurs at `last` within a loop `body`: such an abnormal completion is
 * NOT consumed by the loop (only `break`/`continue` are), so the loop re-emits it as its own last,
 * letting it propagate out to an enclosing `try` or the callable scope.
 */
private predicate loopReEmit(AstNode body, AstNode last, Completion c) {
  last(body, last, c) and (c instanceof ReturnCompletion or c instanceof RaiseCompletion)
}

/**
 * A `while` loop as a real branch with a back-edge: `first` is the condition; condition-true enters
 * the body, the body loops back to the condition (back-edge ⇒ a φ at the loop header, which
 * `definitionReachingValue` lets taint cross), and condition-false exits at the `while` node.
 * `break` in the body exits the loop; `continue` re-checks the condition; `return`/`throw` propagate out.
 */
private class WhileTree extends PostOrderTree instanceof Php::WhileStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) {
    first(this.(Php::WhileStatement).getCondition(), f)
  }

  final override predicate last(AstNode last, Completion c) {
    super.last(last, c) or loopReEmit(this.(Php::WhileStatement).getBody(), last, c)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::WhileStatement s | s = this |
      // condition true -> body
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = true and first(s.getBody(), succ)
      or
      // body ends normally, or with `continue` -> condition (back-edge / re-check)
      last(s.getBody(), pred, c) and
      (c instanceof NormalCompletion or c instanceof ContinueCompletion) and
      first(s.getCondition(), succ)
      or
      // body `break` -> exit
      last(s.getBody(), pred, c) and c instanceof BreakCompletion and succ = this
      or
      // condition false -> exit
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = false and succ = this
    )
  }
}

/**
 * A `do … while` loop: `first` is the body; the body flows to the condition; condition-true loops
 * back to the body (back-edge φ), condition-false exits at the `do` node.
 */
private class DoTree extends PostOrderTree instanceof Php::DoStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::DoStatement).getBody(), f) }

  final override predicate last(AstNode last, Completion c) {
    super.last(last, c) or loopReEmit(this.(Php::DoStatement).getBody(), last, c)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::DoStatement s | s = this |
      // body ends normally, or with `continue` -> condition
      last(s.getBody(), pred, c) and
      (c instanceof NormalCompletion or c instanceof ContinueCompletion) and
      first(s.getCondition(), succ)
      or
      // body `break` -> exit
      last(s.getBody(), pred, c) and c instanceof BreakCompletion and succ = this
      or
      // condition true -> body (back-edge)
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = true and first(s.getBody(), succ)
      or
      // condition false -> exit
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = false and succ = this
    )
  }
}

/** The loop head a `for` returns to after its init / update: its condition if present, else the body. */
private predicate forToHead(Php::ForStatement s, AstNode succ) {
  first(s.getCondition(), succ)
  or
  not exists(s.getCondition()) and first(s.getBody(0), succ)
}

/**
 * A `for (init; cond; update) body` loop as a real branch with a back-edge: `init` runs once, then the
 * condition routes true→body / false→exit; the body flows to `update`, and `update` loops back to the
 * condition (the back-edge ⇒ a φ at the loop header, which `definitionReachingValue` lets taint cross).
 * Each of `init`/`cond`/`update` may be absent; a missing condition makes an unconditional loop whose
 * only exit is `break` (abnormal completions are not yet modelled — AUDIT.md A.6).
 */
private class ForTree extends PostOrderTree instanceof Php::ForStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) {
    exists(Php::ForStatement s | s = this |
      first(s.getInitialize(), f)
      or
      not exists(s.getInitialize()) and first(s.getCondition(), f)
      or
      not exists(s.getInitialize()) and not exists(s.getCondition()) and first(s.getBody(0), f)
    )
  }

  final override predicate last(AstNode last, Completion c) {
    super.last(last, c) or loopReEmit(this.(Php::ForStatement).getBody(_), last, c)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::ForStatement s | s = this |
      // init -> loop head (condition, or body if there is no condition)
      last(s.getInitialize(), pred, c) and c instanceof NormalCompletion and forToHead(s, succ)
      or
      // condition true -> body entry
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = true and first(s.getBody(0), succ)
      or
      // condition false -> exit
      last(s.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = false and succ = this
      or
      // body statement i -> body statement i+1 (alternate `for(...): ... endfor;` syntax)
      exists(int i |
        last(s.getBody(i), pred, c) and c instanceof NormalCompletion and first(s.getBody(i + 1), succ)
      )
      or
      // last body statement (normal) -> update (or head if no update)
      exists(int i |
        last(s.getBody(i), pred, c) and not exists(s.getBody(i + 1)) and c instanceof NormalCompletion
      |
        first(s.getUpdate(), succ)
        or
        not exists(s.getUpdate()) and forToHead(s, succ)
      )
      or
      // body `continue` -> update (or head if no update)
      last(s.getBody(_), pred, c) and
      c instanceof ContinueCompletion and
      (first(s.getUpdate(), succ) or not exists(s.getUpdate()) and forToHead(s, succ))
      or
      // body `break` -> exit
      last(s.getBody(_), pred, c) and c instanceof BreakCompletion and succ = this
      or
      // update -> condition (the back-edge; or body head if there is no condition)
      last(s.getUpdate(), pred, c) and c instanceof NormalCompletion and forToHead(s, succ)
    )
  }
}

/** Gets the binding pattern of a `foreach` (the value, or `$k => $v` pair, or `[...]` — child index >= 1). */
private AstNode foreachBinding(Php::ForeachStatement f) {
  exists(int i | i >= 1 and result = f.getChild(i))
}

/**
 * A `foreach (coll as pattern) body` loop with a back-edge. The collection is evaluated once (`first`),
 * then the binding pattern acts as the loop header: it binds the next element and enters the body, the
 * body loops back to the header (back-edge ⇒ a φ at the header), and the loop exits from the header
 * (no more elements) or directly from the collection (empty). The tainted-collection→loop-variable step
 * is provided separately as a taint step; here we only wire control flow.
 */
private class ForeachTree extends PostOrderTree instanceof Php::ForeachStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::ForeachStatement).getChild(0), f) }

  final override predicate last(AstNode last, Completion c) {
    super.last(last, c) or loopReEmit(this.(Php::ForeachStatement).getBody(), last, c)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::ForeachStatement s | s = this |
      // collection -> header (bind first element)
      last(s.getChild(0), pred, c) and c instanceof NormalCompletion and first(foreachBinding(s), succ)
      or
      // header (element bound) -> body
      last(foreachBinding(s), pred, c) and c instanceof NormalCompletion and first(s.getBody(), succ)
      or
      // body ends normally or with `continue` -> header (back-edge: bind the next element)
      last(s.getBody(), pred, c) and
      (c instanceof NormalCompletion or c instanceof ContinueCompletion) and
      first(foreachBinding(s), succ)
      or
      // body `break` -> exit
      last(s.getBody(), pred, c) and c instanceof BreakCompletion and succ = this
      or
      // exit: no more elements (from the header) or an empty collection (from the collection)
      (last(foreachBinding(s), pred, c) or last(s.getChild(0), pred, c)) and
      c instanceof NormalCompletion and
      succ = this
    )
  }
}

/** Gets the `i`th case/default arm of a `switch`, in source order. */
private AstNode switchCase(Php::SwitchStatement s, int i) { result = s.getBody().getChild(i) }

/**
 * A `switch ($subject) { case v: … case w: … default: … }`. The subject is evaluated, then routed to
 * any arm (non-deterministic — no per-case value splitting). Arms FALL THROUGH to the next arm on a
 * normal completion; a `break` in an arm exits the switch (this is the ONLY way to isolate arms, exactly
 * as in PHP). `continue`/`return`/`throw` are re-emitted so they reach the enclosing loop / callable.
 */
private class SwitchTree extends PostOrderTree instanceof Php::SwitchStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::SwitchStatement).getCondition(), f) }

  final override predicate last(AstNode last, Completion c) {
    super.last(last, c)
    or
    // everything abnormal EXCEPT `break` (which the switch consumes) propagates out.
    last(switchCase(this, _), last, c) and
    (c instanceof ContinueCompletion or c instanceof ReturnCompletion or c instanceof RaiseCompletion)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::SwitchStatement s | s = this |
      // subject -> any arm
      last(s.getCondition(), pred, c) and c instanceof NormalCompletion and first(switchCase(s, _), succ)
      or
      // arm i falls through to arm i+1 on a normal completion
      exists(int i |
        last(switchCase(s, i), pred, c) and c instanceof NormalCompletion and first(switchCase(s, i + 1), succ)
      )
      or
      // last arm falls out of the switch
      exists(int i |
        last(switchCase(s, i), pred, c) and c instanceof NormalCompletion and not exists(switchCase(s, i + 1))
      ) and
      succ = this
      or
      // `break` in any arm exits the switch (arm isolation)
      last(switchCase(s, _), pred, c) and c instanceof BreakCompletion and succ = this
    )
  }
}

/** Gets a `catch` clause of a `try`. */
private Php::CatchClause tryCatch(Php::TryStatement t) { result = t.getChild(_) }

/**
 * Holds if `call` is in the body of `try` `t` and calls a function or method whose body contains a
 * `throw` — so the call may raise into the `try`'s catch. Callees are resolved by name (an
 * over-approximation, matching how the exceptional call edge itself over-approximates).
 */
private predicate throwingCallInTry(Php::TryStatement t, AstNode call) {
  call.(Php::AstNode).getParent+() = t.getBody() and
  (
    exists(Php::FunctionDefinition callee |
      callee.getName().getValue() = call.(Php::FunctionCallExpression).getFunction().(Php::Name).getValue() and
      exists(Php::ThrowExpression thr | thr.(Php::AstNode).getParent+() = callee.getBody())
    )
    or
    exists(Php::MethodDeclaration callee |
      callee.getName().getValue() = call.(Php::MemberCallExpression).getName().(Php::Name).getValue() and
      exists(Php::ThrowExpression thr | thr.(Php::AstNode).getParent+() = callee.getBody())
    )
  )
}

/** Gets the `finally` clause of a `try`, if any. */
private Php::FinallyClause tryFinally(Php::TryStatement t) { result = t.getChild(_) }

/** The point a `try`/`catch` body flows to after completing normally: the `finally`, else the try node. */
private predicate tryToFinallyOrExit(Php::TryStatement t, AstNode succ) {
  first(tryFinally(t).getBody(), succ)
  or
  not exists(tryFinally(t)) and succ = t
}

/**
 * A `try { … } catch (E $e) { … } finally { … }`. The try body runs; on a `throw` it routes to a catch
 * clause (any — no exception-type matching in v1, a sound over-approximation), which binds `$e` and runs
 * its body; normal completion of the try or a catch flows through `finally` (if present) to the exit.
 * `return`/uncaught `throw`/`break`/`continue` from the try or catch bodies propagate out.
 */
private class TryTree extends PostOrderTree instanceof Php::TryStatement {
  final override predicate propagatesAbnormal(AstNode child) {
    child = this.(Php::TryStatement).getBody() or child = tryCatch(this).getBody()
  }

  final override predicate first(AstNode f) { first(this.(Php::TryStatement).getBody(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::TryStatement t | t = this |
      // try body throws -> a catch clause (any)
      last(t.getBody(), pred, c) and c instanceof RaiseCompletion and first(tryCatch(t), succ)
      or
      // try body calls a function/method that can throw -> a catch clause (any). Calls do not produce a
      // `RaiseCompletion` (the CFG does not track which callee raises), so a body containing a call to a
      // throwing function/method is over-approximated as able to reach the catch on its normal exit —
      // enough to linearise the catch binding (giving `$e` an SSA definition) and route the thrown value
      // to it (see `DataFlowPrivate`). This mirrors the exceptional call edges other language packs build.
      last(t.getBody(), pred, c) and
      c instanceof NormalCompletion and
      throwingCallInTry(t, _) and
      first(tryCatch(t), succ)
      or
      // try body completes normally -> finally / exit
      last(t.getBody(), pred, c) and c instanceof NormalCompletion and tryToFinallyOrExit(t, succ)
      or
      // a catch clause completes normally -> finally / exit
      last(tryCatch(t), pred, c) and c instanceof NormalCompletion and tryToFinallyOrExit(t, succ)
      or
      // finally completes -> exit
      last(tryFinally(t).getBody(), pred, c) and c instanceof NormalCompletion and succ = this
    )
  }
}

/** Holds if `e` is a short-circuit binary operator (`&&`/`||`/`and`/`or`/`??`), modelled as a branch. */
private predicate isShortCircuit(AstNode e) {
  e.(Php::BinaryExpression).getOperator() = ["&&", "||", "and", "or", "??"]
}

/**
 * A short-circuit `&&` / `and`: the left operand is evaluated; false short-circuits to the result
 * (right not evaluated), true evaluates the right operand; both meet at the operation node (post-order
 * root) ⇒ a real branch/join. Taint through either operand is carried by `structuralPropagator`.
 */
private class LogicalAndTree extends PostOrderTree instanceof Php::BinaryExpression {
  LogicalAndTree() { this.(Php::BinaryExpression).getOperator() = ["&&", "and"] }

  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::BinaryExpression).getLeft(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::BinaryExpression b | b = this |
      last(b.getLeft(), pred, c) and c.(BooleanCompletion).getValue() = true and first(b.getRight(), succ)
      or
      last(b.getLeft(), pred, c) and c.(BooleanCompletion).getValue() = false and succ = this
      or
      last(b.getRight(), pred, c) and c instanceof NormalCompletion and succ = this
    )
  }
}

/** A short-circuit `||` / `or`: left true short-circuits to the result; left false evaluates the right. */
private class LogicalOrTree extends PostOrderTree instanceof Php::BinaryExpression {
  LogicalOrTree() { this.(Php::BinaryExpression).getOperator() = ["||", "or"] }

  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::BinaryExpression).getLeft(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::BinaryExpression b | b = this |
      last(b.getLeft(), pred, c) and c.(BooleanCompletion).getValue() = false and first(b.getRight(), succ)
      or
      last(b.getLeft(), pred, c) and c.(BooleanCompletion).getValue() = true and succ = this
      or
      last(b.getRight(), pred, c) and c instanceof NormalCompletion and succ = this
    )
  }
}

/**
 * A null-coalescing `??`: the left operand is evaluated; if non-null it IS the result (short-circuit),
 * if null the right operand is evaluated. `??` tests null-ness, not a boolean, so — lacking a nullness
 * completion — the branch is modelled non-deterministically (both edges from the left), a sound
 * over-approximation. Taint through either operand is carried by `structuralPropagator`.
 */
private class NullCoalesceTree extends PostOrderTree instanceof Php::BinaryExpression {
  NullCoalesceTree() { this.(Php::BinaryExpression).getOperator() = "??" }

  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::BinaryExpression).getLeft(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::BinaryExpression b | b = this |
      last(b.getLeft(), pred, c) and c instanceof NormalCompletion and
      (succ = this or first(b.getRight(), succ))
      or
      last(b.getRight(), pred, c) and c instanceof NormalCompletion and succ = this
    )
  }
}

/**
 * An expression, evaluated in post-order: its operands are visited first, then the expression
 * node itself. Childless expressions (variables, literals, names) behave as leaves. Short-circuit
 * binary operators are excluded — they branch instead (`LogicalAndTree`/`LogicalOrTree`/`NullCoalesceTree`).
 */
private class ExprTree extends StandardPostOrderTree instanceof Php::Expression {
  ExprTree() {
    not isCallable(this) and
    not isShortCircuit(this) and
    not this instanceof Php::MatchExpression and
    not this instanceof Php::ThrowExpression and
    not this instanceof Php::ConditionalExpression and
    not isAssignment(this)
  }

  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }
}

/** Holds if `n` is an assignment (`=`, augmented `.=`/`+=`/…, or reference `=&`). */
private predicate isAssignment(AstNode n) {
  n instanceof Php::AssignmentExpression or
  n instanceof Php::AugmentedAssignmentExpression or
  n instanceof Php::ReferenceAssignmentExpression
}

/** Gets the left-hand (target) side of an assignment `n`. */
private AstNode assignLhs(AstNode n) {
  result = n.(Php::AssignmentExpression).getLeft() or
  result = n.(Php::AugmentedAssignmentExpression).getLeft() or
  result = n.(Php::ReferenceAssignmentExpression).getLeft()
}

/** Gets the right-hand (value) side of an assignment `n`. */
private AstNode assignRhs(AstNode n) {
  result = n.(Php::AssignmentExpression).getRight() or
  result = n.(Php::AugmentedAssignmentExpression).getRight() or
  result = n.(Php::ReferenceAssignmentExpression).getRight()
}

/**
 * An assignment `$lhs = rhs` (or `.=`/`+=`/… / `=&`): the RHS is evaluated BEFORE the target is written,
 * regardless of source position. Ordering the target last is what makes a self-referential assignment
 * `$a = f($a)` correct — the read of `$a` inside the RHS sees the PRIOR definition, not the one being
 * written (a textual left-to-right order would create a spurious SSA self-cycle and drop the taint).
 */
private class AssignmentTree extends StandardPostOrderTree instanceof AstNode {
  AssignmentTree() { isAssignment(this) }

  override ControlFlowTree getChildNode(int i) {
    result = assignRhs(this) and i = 0
    or
    result = assignLhs(this) and i = 1
  }
}

/**
 * A ternary `c ? a : b` (or elvis `c ?: b`): the condition routes true→`a` / false→`b`, both meeting at
 * the conditional node (post-order root) ⇒ a real branch/join. For elvis, a true condition IS the value,
 * so it flows straight to the result. Taint through the branches is carried by `defaultAdditionalTaintStep`.
 */
private class TernaryTree extends PostOrderTree instanceof Php::ConditionalExpression {
  final override predicate propagatesAbnormal(AstNode child) {
    child = this.(Php::ConditionalExpression).getBody() or
    child = this.(Php::ConditionalExpression).getAlternative()
  }

  final override predicate first(AstNode f) { first(this.(Php::ConditionalExpression).getCondition(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::ConditionalExpression ce | ce = this |
      // condition true -> `a` (or, for elvis `c ?: b`, straight to the result)
      last(ce.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = true and
      (first(ce.getBody(), succ) or not exists(ce.getBody()) and succ = this)
      or
      // condition false -> `b`
      last(ce.getCondition(), pred, c) and c.(BooleanCompletion).getValue() = false and
      first(ce.getAlternative(), succ)
      or
      // a branch completes -> the ternary result
      (last(ce.getBody(), pred, c) or last(ce.getAlternative(), pred, c)) and
      c instanceof NormalCompletion and
      succ = this
    )
  }
}

/**
 * An abnormal-completion producer: `break`/`continue`/`return`/`throw`. Its operand (a break/continue
 * level, a return value, a thrown expression — if any) is evaluated first, then the statement itself
 * completes with the matching abnormal completion (`BreakCompletion`/…) and has NO normal successor, so
 * it does not fall through to the next statement. The completion propagates up until a construct
 * consumes it (`ClosingTree` in loops/switch, `TryTree`, or the callable scope for return/throw).
 */
private class AbnormalProducerTree extends StandardPostOrderTree instanceof AstNode {
  AbnormalProducerTree() {
    this instanceof Php::BreakStatement or
    this instanceof Php::ContinueStatement or
    this instanceof Php::ReturnStatement or
    this instanceof Php::ThrowExpression
  }

  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }
}

/**
 * A `match ($subject) { conds => r, …, default => r }` expression: the subject is evaluated, then
 * exactly one arm is selected and its return produces the value. Arms do NOT fall through. The subject
 * routes to any arm (non-deterministic selection — no per-arm condition splitting), and each arm meets
 * at the match node (post-order root). The selected arm's return taints the result via a taint step
 * (`defaultAdditionalTaintStep`); here we only wire control flow.
 */
private class MatchTree extends PostOrderTree instanceof Php::MatchExpression {
  final override predicate propagatesAbnormal(AstNode child) {
    child = this.(Php::MatchExpression).getBody().getChild(_)
  }

  final override predicate first(AstNode f) { first(this.(Php::MatchExpression).getCondition(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(Php::MatchExpression m | m = this |
      // subject evaluated -> an arm (non-deterministic selection)
      last(m.getCondition(), pred, c) and
      c instanceof NormalCompletion and
      first(m.getBody().getChild(_), succ)
      or
      // an arm evaluated -> the match result
      last(m.getBody().getChild(_), pred, c) and c instanceof NormalCompletion and succ = this
    )
  }
}

/**
 * A callable, whose own CFG scope flows through its parameters (with default values) and then its
 * body. In its *enclosing* scope the callable is a single leaf node (post-order root), because its
 * children belong to the callable's scope.
 */
private class CallableTree extends PostOrderTree instanceof AstNode {
  CallableTree() { isCallable(this) }

  final override predicate propagatesAbnormal(AstNode child) { none() }

  override predicate first(AstNode f) { f = this }

  override predicate succ(AstNode pred, AstNode succ, Completion c) {
    exists(int i |
      last(callableBodyChild(this, i), pred, c) and
      first(callableBodyChild(this, i + 1), succ) and
      c instanceof NormalCompletion
    )
  }
}

/** A type declaration is a leaf in its enclosing scope (its methods are separate scopes). */
private class TypeDeclarationLeaf extends LeafTree instanceof AstNode {
  TypeDeclarationLeaf() { isTypeDeclaration(this) }
}

/**
 * The `$e` binding of a `catch (E $e)` is a leaf CFG node — a definition of `$e` reached first when the
 * `try` raises (`TryTree` routes the raise to `first(catch)`). Without this the binding is not linearised
 * into the CFG, so it never becomes a `variableWrite` and `$e` is an SSA orphan (taint cannot reach it
 * through the engine). Making it a node gives `$e` a proper SSA definition, like a `foreach` value
 * binding, so a thrown value routed to it (see `DataFlowPrivate`) flows to every `$e` read.
 */
private class CatchVarLeaf extends LeafTree instanceof Php::VariableName {
  CatchVarLeaf() { this = any(Php::CatchClause c).getName() }
}
