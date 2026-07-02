/**
 * @kind table
 * @id php/test/frameworks
 * @description Taint through WordPress/Symfony/Doctrine/PrestaShop/TYPO3 core APIs (data models).
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
  exists(DataFlow::Node src, DataFlow::Node snk |
    Flow::flow(src, snk) and line = snk.getLocation().getStartLine() and kind = snk.(Sink).getKind()
  )
}
