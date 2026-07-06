/**
 * @name Templating output (XSS) + template injection (SSTI) coverage
 * @kind table
 * @id php/test/templating
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module XssCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "reflected XSS" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module SstiCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "template injection" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module XssFlow = TaintTracking::Global<XssCfg>;

module SstiFlow = TaintTracking::Global<SstiCfg>;

query predicate reaches(int sinkLine, string kind) {
  exists(DataFlow::Node sink |
    XssFlow::flowTo(sink) and sinkLine = sink.getLocation().getStartLine() and kind = "xss"
  )
  or
  exists(DataFlow::Node sink |
    SstiFlow::flowTo(sink) and sinkLine = sink.getLocation().getStartLine() and kind = "ssti"
  )
}
