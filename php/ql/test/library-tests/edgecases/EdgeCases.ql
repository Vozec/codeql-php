/**
 * @kind table
 * @id php/test/edgecases
 */
import php
import codeql.php.dataflow.TaintTracking
query predicate flows(int sinkLine, string kind) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    TaintTracking::hasTaintFlow(src, sink, kind) and sinkLine = sink.getLocation().getStartLine()
  )
}
