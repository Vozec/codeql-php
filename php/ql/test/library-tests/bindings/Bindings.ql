/**
 * @kind table
 * @id php/test/bindings
 */
import php
import codeql.php.dataflow.TaintTracking

query predicate flows(int sinkLine, string kind, int sourceLine) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    TaintTracking::hasTaintFlow(src, sink, kind) and
    sinkLine = sink.getLocation().getStartLine() and
    sourceLine = src.getLocation().getStartLine()
  )
}
