/**
 * @name XML external entity expansion
 * @description Parsing user-controlled XML with external-entity or DTD loading enabled (an unsafe libxml
 *              flag) allows XXE — file disclosure, SSRF, or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id php/xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "xxe" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This XML parse depends on a $@ and loads external entities.",
  source.getNode(), "user-provided value"
