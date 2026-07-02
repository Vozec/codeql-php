/**
 * @kind table
 * @id php/test/dataflow
 */
import php
import codeql.php.dataflow.DataFlow

query predicate localSteps(int fromLine, string fromKind, int toLine, string toKind) {
  exists(DataFlow::Node a, DataFlow::Node b |
    DataFlow::localFlowStep(a, b) and
    fromLine = a.getLocation().getStartLine() and fromKind = a.asExpr().getPrimaryQlClass() and
    toLine = b.getLocation().getStartLine() and toKind = b.asExpr().getPrimaryQlClass()
  )
}
