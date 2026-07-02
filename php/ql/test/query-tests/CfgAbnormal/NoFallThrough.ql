/**
 * A.6 structural test: `return` / `break` / `continue` / `throw` must NOT fall through to the
 * following statement in their block — an abnormal completion transfers control elsewhere, so the
 * next sibling is unreachable from them. Any producer whose CFG successor lands inside its next
 * sibling is reported; the expected output is EMPTY.
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

from Php::CompoundStatement blk, int i, Php::AstNode s, Php::AstNode next, CfgNode sn, CfgNode succ
where
  s = blk.getChild(i) and
  next = blk.getChild(i + 1) and
  abnormalProducer(s) and
  sn.getAstNode() = s and
  succ = sn.getASuccessor() and
  succ.getAstNode().getParent*() = next
select s, "abnormal producer falls through to the next statement (should be cut)"
