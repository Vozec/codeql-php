/**
 * @name Control-flow-graph consistency
 * @description Reports CFG blind spots: (1) runtime expressions/statements not part of any CFG, and
 *   (2) branching constructs that are LINEARISED — modelled as a straight line with no real
 *   alternative edges, so control- and data-flow silently leak between branches. Anything reported
 *   here (other than PHP attribute contents, which run only via reflection) should be investigated.
 * @kind problem
 * @problem.severity warning
 * @id php/consistency/cfg-coverage
 */

import php
import codeql.php.controlflow.ControlFlowGraph
import codeql.php.ast.internal.TreeSitter

/**
 * Holds if `n` is in a position that is not part of runtime control flow and is therefore
 * legitimately excluded from the CFG: attribute contents (evaluated only via reflection), and
 * constant initializers (property/const/enum-case defaults, which PHP requires to be constant
 * expressions and so can never carry data flow).
 */
predicate inNonRuntimePosition(AstNode n) {
  n.getParent*() instanceof Php::AttributeList or
  n.getParent*() instanceof Php::PropertyDeclaration or
  n.getParent*() instanceof Php::ConstDeclaration or
  n.getParent*() instanceof Php::EnumCase
}

/** A node whose value is not covered by any control-flow node. */
predicate uncoveredNode(AstNode n) {
  (n instanceof Php::Statement or n instanceof Php::Expression) and
  not exists(CfgNode c | c.getAstNode() = n) and
  not inNonRuntimePosition(n) and
  // callables are represented in their enclosing scope by a single node (they have their own scope)
  not n instanceof Php::AnonymousFunction and
  not n instanceof Php::ArrowFunction and
  // bare name / type references are not evaluated as expressions
  not n instanceof Php::Name and
  not n instanceof Php::QualifiedName and
  // `;` empty statements are no-ops with no control flow
  not n instanceof Php::EmptyStatement and
  // closure `use (...)` capture clauses are a known, separately-modelled case (not runtime flow here)
  not n.getParent*() instanceof Php::AnonymousFunctionUseClause
}

/**
 * Holds if `n` is a construct that MUST introduce a control-flow branch (two or more alternative
 * successors): conditionals, loops, multi-way selection, short-circuit operators. This is the
 * ground truth against which the CFG is checked — it is a property of the *language*, not of the
 * current (partial) CFG model, so a construct listed here that turns out linearised is a real gap.
 */
predicate mustBranch(AstNode n) {
  n instanceof Php::IfStatement or
  n instanceof Php::WhileStatement or
  n instanceof Php::DoStatement or
  n instanceof Php::ForStatement or
  n instanceof Php::ForeachStatement or
  n instanceof Php::SwitchStatement or
  n instanceof Php::MatchExpression or
  n instanceof Php::ConditionalExpression or
  n.(Php::BinaryExpression).getOperator() = ["&&", "||", "and", "or", "??"]
}

/** Holds if some control-flow node inside `construct`'s subtree really branches (>= 2 successors). */
predicate hasRealBranch(AstNode construct) {
  exists(CfgNode c |
    c.getAstNode().getParent*() = construct and
    count(CfgNode s | s = c.getASuccessor()) >= 2
  )
}

/**
 * Holds if `n` is a branching construct that is LINEARISED: no node in its subtree branches. Nested
 * branching children can mask an outer gap here (they make `hasRealBranch` hold for the outer), so a
 * clean result is necessary-but-not-sufficient; the per-construct query-tests (BranchTaint, LoopTaint)
 * are the positive checks. Still, this surfaces every wholly-linearised construct (today: `for`,
 * `foreach`, `switch`, `match`, `&&`/`||`/`??`, ternary — see AUDIT.md Phase A).
 */
predicate linearisedBranch(AstNode n) { mustBranch(n) and not hasRealBranch(n) }

from AstNode n, string msg
where
  uncoveredNode(n) and
  msg = "This " + n.getPrimaryQlClass() + " is not covered by the control-flow graph."
  or
  linearisedBranch(n) and
  msg =
    "This " + n.getPrimaryQlClass() +
      " must branch but is linearised in the CFG (no alternative edges) — control/data flow leaks between its branches."
select n, msg
