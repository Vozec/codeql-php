/**
 * @kind table
 * @id php/test/cfg
 */
import php

query predicate edges(int predLine, string predKind, int succLine, string succKind) {
  exists(AstCfgNode a, AstCfgNode b |
    b = a.getASuccessor() and
    predLine = a.getLocation().getStartLine() and predKind = a.getAstNode().getPrimaryQlClass() and
    succLine = b.getLocation().getStartLine() and succKind = b.getAstNode().getPrimaryQlClass()
  )
}
