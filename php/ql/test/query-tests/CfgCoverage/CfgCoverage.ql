/**
 * CFG coverage battery: over a source file exercising EVERY control construct (if/elseif/else,
 * while/do/for/foreach with break/continue, switch with fall-through and break, match, try/catch/
 * finally, ternary/elvis, `&&`/`||`/`??`, return + dead code), assert there are NO blind spots:
 *  - no runtime statement/expression is missing from the CFG (except provably-dead code), and
 *  - every construct that must branch actually has alternative edges.
 * The expected output is EMPTY; this is the regression lock for the whole CFG.
 */

import php
import codeql.php.ast.internal.TreeSitter
import codeql.php.controlflow.ControlFlowGraph

private predicate abnormalProducer(Php::AstNode s) {
  s instanceof Php::ReturnStatement or
  s instanceof Php::BreakStatement or
  s instanceof Php::ContinueStatement or
  s instanceof Php::ThrowExpression
}

private predicate unreachableAfterAbnormal(AstNode n) {
  exists(Php::CompoundStatement blk, int i, int j |
    abnormalProducer(blk.getChild(i)) and n.getParent*() = blk.getChild(j) and j > i
  )
}

private predicate inNonRuntimePosition(AstNode n) {
  n.getParent*() instanceof Php::AttributeList or
  n.getParent*() instanceof Php::PropertyDeclaration or
  n.getParent*() instanceof Php::ConstDeclaration or
  n.getParent*() instanceof Php::EnumCase
}

private predicate uncovered(AstNode n) {
  (n instanceof Php::Statement or n instanceof Php::Expression) and
  not exists(CfgNode c | c.getAstNode() = n) and
  not inNonRuntimePosition(n) and
  not unreachableAfterAbnormal(n) and
  not n instanceof Php::AnonymousFunction and
  not n instanceof Php::ArrowFunction and
  not n instanceof Php::Name and
  not n instanceof Php::QualifiedName and
  not n instanceof Php::EmptyStatement and
  not n.getParent*() instanceof Php::AnonymousFunctionUseClause
}

private predicate mustBranch(AstNode n) {
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

private predicate linearised(AstNode n) {
  mustBranch(n) and
  not exists(CfgNode c |
    c.getAstNode().getParent*() = n and count(CfgNode s | s = c.getASuccessor()) >= 2
  )
}

from AstNode n, string msg
where
  uncovered(n) and msg = "uncovered: " + n.getPrimaryQlClass()
  or
  linearised(n) and msg = "linearised: " + n.getPrimaryQlClass()
select n, msg
