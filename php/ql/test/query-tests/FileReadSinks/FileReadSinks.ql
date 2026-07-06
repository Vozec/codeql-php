/**
 * @name File read sinks
 * @kind table
 * @id php/test/file-read-sinks
 */
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "file read" }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}
module Flow = TaintTracking::Global<Cfg>;
query predicate reaches(int sinkLine) {
  exists(DataFlow::Node s | Flow::flowTo(s) and sinkLine = s.getLocation().getStartLine())
}
