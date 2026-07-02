/**
 * @name Server-side request forgery
 * @description User input reaches a outbound request, enabling Server-side request forgery.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision high
 * @id php/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "server-side request forgery" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This outbound request depends on a $@.", source.getNode(),
  "user-provided value"
