/**
 * @name Complex flows batch 5
 * @kind table
 * @id php/test/complex-flows5
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = ["command injection", "SQL injection"] }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

query predicate reaches(int sinkLine) {
  exists(DataFlow::Node sink | Flow::flowTo(sink) and sinkLine = sink.getLocation().getStartLine())
}
