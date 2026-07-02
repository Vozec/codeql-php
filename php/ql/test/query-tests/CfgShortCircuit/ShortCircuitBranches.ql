/**
 * A.5 consistency test: every short-circuit operator (`&&`, `||`, `??`, and the low-precedence
 * `and`/`or`) must introduce a real control-flow branch — some CFG node in its subtree has two or
 * more successors. A linearised operator (no alternative edges) is reported; the expected output is
 * EMPTY, so this stays green only while short-circuit branching is modelled.
 */

import php
import codeql.php.ast.internal.TreeSitter
import codeql.php.controlflow.ControlFlowGraph

from Php::BinaryExpression b
where
  b.getOperator() = ["&&", "||", "and", "or", "??"] and
  not exists(CfgNode c |
    c.getAstNode().getParent*() = b and count(CfgNode s | s = c.getASuccessor()) >= 2
  )
select b, "short-circuit operator '" + b.getOperator() + "' is linearised (no branch edges)"
