/**
 * @name PHP construct taint coverage
 * @description Exercises the PRODUCTION (shared) taint engine — identical config to the real security
 *              queries (e.g. CommandInjection.ql) — so a construct that stops carrying taint regresses
 *              here. Reports the (sink line, source line) of every command-injection flow.
 * @kind table
 * @id php/test/construct-coverage
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "command injection" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

query predicate taintReaches(int sinkLine, int sourceLine) {
  exists(DataFlow::Node src, DataFlow::Node sink |
    Flow::flow(src, sink) and
    sinkLine = sink.getLocation().getStartLine() and
    sourceLine = src.getLocation().getStartLine()
  )
}
