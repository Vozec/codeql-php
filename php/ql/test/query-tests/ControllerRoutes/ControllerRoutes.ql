/**
 * @name Controller route-parameter taint coverage
 * @description A route parameter reaching a SQL sink through a controller action, several calls deep.
 *              Uses the production shared engine (config identical to SqlInjection.ql).
 * @kind table
 * @id php/test/controller-routes
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "SQL injection" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

query predicate taintReaches(int sinkLine, string sourceKind) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    Flow::flow(src, sink) and
    sinkLine = sink.getLocation().getStartLine() and
    sourceKind = src.(RemoteFlowSource).getSourceType()
  )
}
