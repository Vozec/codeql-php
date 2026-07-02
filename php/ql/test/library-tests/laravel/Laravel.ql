/**
 * @kind table
 * @id php/test/laravel
 * @description Taint reaches sinks through Laravel core APIs modelled as data (no vendor/ extracted).
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) { exists(n.(Sink).getKind()) }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

query predicate vuln(int line, string kind) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    Flow::flow(src, sink) and
    line = sink.getLocation().getStartLine() and
    kind = sink.(Sink).getKind()
  )
}
