/**
 * @name Server-side template injection
 * @description User input used as a template (rather than as template data) is compiled and executed
 *              by the template engine, enabling server-side template injection and code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id php/template-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-1336
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "template injection" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This template depends on a $@.", source.getNode(),
  "user-provided value"
