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
    TReturnCompletion()

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
    }

    override BooleanSuccessor getAMatchingSuccessorType() { result.getValue() = value }

    final boolean getValue() { result = value }
  }

  class ReturnCompletion extends Completion, TReturnCompletion {
    override string toString() { result = "ReturnCompletion" }

    override ReturnSuccessor getAMatchingSuccessorType() { any() }
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

  final override predicate propagatesAbnormal(AstNode child) { none() }

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
 * A `while` loop as a real branch with a back-edge: `first` is the condition; condition-true enters
 * the body, the body loops back to the condition (back-edge ⇒ a φ at the loop header, which
 * `definitionReachingValue` lets taint cross), and condition-false exits at the `while` node.
 * `break`/`continue` are (conservatively) left to normal sequencing for now.
 */
private class WhileTree extends PostOrderTree instanceof Php::WhileStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) {
    first(this.(Php::WhileStatement).getCondition(), f)
  }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    // condition true -> body
    last(this.(Php::WhileStatement).getCondition(), pred, c) and
    c.(BooleanCompletion).getValue() = true and
    first(this.(Php::WhileStatement).getBody(), succ)
    or
    // body -> condition (back-edge)
    last(this.(Php::WhileStatement).getBody(), pred, c) and
    first(this.(Php::WhileStatement).getCondition(), succ) and
    c instanceof NormalCompletion
    or
    // condition false -> exit
    last(this.(Php::WhileStatement).getCondition(), pred, c) and
    c.(BooleanCompletion).getValue() = false and
    succ = this
  }
}

/**
 * A `do … while` loop: `first` is the body; the body flows to the condition; condition-true loops
 * back to the body (back-edge φ), condition-false exits at the `do` node.
 */
private class DoTree extends PostOrderTree instanceof Php::DoStatement {
  final override predicate propagatesAbnormal(AstNode child) { none() }

  final override predicate first(AstNode f) { first(this.(Php::DoStatement).getBody(), f) }

  final override predicate succ(AstNode pred, AstNode succ, Completion c) {
    // body -> condition
    last(this.(Php::DoStatement).getBody(), pred, c) and
    first(this.(Php::DoStatement).getCondition(), succ) and
    c instanceof NormalCompletion
    or
    // condition true -> body (back-edge)
    last(this.(Php::DoStatement).getCondition(), pred, c) and
    c.(BooleanCompletion).getValue() = true and
    first(this.(Php::DoStatement).getBody(), succ)
    or
    // condition false -> exit
    last(this.(Php::DoStatement).getCondition(), pred, c) and
    c.(BooleanCompletion).getValue() = false and
    succ = this
  }
}

/**
 * An expression, evaluated in post-order: its operands are visited first, then the expression
 * node itself. Childless expressions (variables, literals, names) behave as leaves.
 */
private class ExprTree extends StandardPostOrderTree instanceof Php::Expression {
  ExprTree() { not isCallable(this) }

  override ControlFlowTree getChildNode(int i) { result = rankedCfgChild(this, i) }
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
