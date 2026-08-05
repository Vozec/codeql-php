/**
 * @name Open redirect
 * @description User input reaches a HTTP header, enabling Open redirect.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id php/open-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

/**
 * Holds when `n` is an operand of a string concatenation whose destination host is already pinned by
 * a constant absolute-URL prefix to its left — e.g. `header("Location: https://site.tld" . $userPath)`.
 * Appending user input to a fixed `scheme://host` base only controls the path, not the target host, so
 * it is not an open redirect. Requires a *constant* scheme+host literal, so it does NOT clear the
 * genuinely-unsafe cases where the prefix is a bare `"Location: "` or a spoofable value (`$_SERVER['HTTP_HOST']`).
 */
private predicate hostPinnedConcatOperand(DataFlow::Node n) {
  exists(ConcatExpr ce |
    ce.getRightOperand() = n.asExpr() and
    ce.getLeftOperand().(StringLiteral).getValue().regexpMatch("(?s).*https?://[A-Za-z0-9._~%-]+.*")
  )
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "open redirect" }

  predicate isBarrier(DataFlow::Node n) {
    n instanceof Sanitizer
    or
    hostPinnedConcatOperand(n)
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This HTTP header depends on a $@.", source.getNode(),
  "user-provided value"
