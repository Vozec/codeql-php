/**
 * @name LDAP injection
 * @description User input concatenated into an LDAP filter or DN without escaping enables LDAP
 *              injection (authentication bypass, unauthorized attribute disclosure).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id php/ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "ldap injection" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This LDAP query depends on a $@.", source.getNode(),
  "user-provided value"
