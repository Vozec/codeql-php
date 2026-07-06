/** @name fw @kind table @id php/test/fw */
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = ["SQL injection", "open redirect"] }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}
module Flow = TaintTracking::Global<Cfg>;
query predicate reaches(int line) { exists(DataFlow::Node s | Flow::flowTo(s) and line=s.getLocation().getStartLine()) }
