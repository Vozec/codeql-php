/**
 * @name Control-flow-graph consistency
 * @description Runtime expressions and statements that are not part of any control-flow graph.
 *   Anything reported here (other than PHP attribute contents, which run only via reflection) is a
 *   coverage blind spot in the CFG and should be investigated.
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

from AstNode n
where
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
select n, "This " + n.getPrimaryQlClass() + " is not covered by the control-flow graph."
