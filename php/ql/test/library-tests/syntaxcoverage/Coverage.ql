/**
 * @kind table
 * @id php/test/syntax-coverage
 * @description Records which call/assignment/flow syntaxes are covered by taint tracking.
 */
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = ["command injection", "code injection"] }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

query predicate covered(string file, int line) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    Flow::flow(src, sink) and
    file = sink.getLocation().getFile().getBaseName() and
    line = sink.getLocation().getStartLine()
  )
}
