/**
 * @name Unsafe Laravel validator (user-controlled Rule::unique/exists ignore)
 * @description A user-controlled value passed to `Rule::unique(...)->ignore()` /
 *              `Rule::exists(...)->ignore()` lets an attacker exclude an arbitrary row from the check,
 *              bypassing the uniqueness/existence validation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision high
 * @id php/unsafe-validator
 * @tags security
 *       external/cwe/cwe-639
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "validation bypass" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This validator `ignore()` depends on a $@, allowing the uniqueness check to be bypassed.",
  source.getNode(), "user-provided value"
