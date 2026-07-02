/**
 * @name Hard-coded cryptographic key
 * @description Using a hard-coded constant as a cryptographic key/salt/password compromises secrecy.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id php/hardcoded-crypto-key
 * @tags security external/cwe/cwe-798 external/cwe/cwe-321
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
import codeql.php.AST

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    // A non-empty constant string literal (single- or double-quoted, without interpolated variables).
    exists(StringLiteral s | n.asExpr() = s and s.hasContent() and s.isConstant())
  }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "hardcoded-crypto-key" }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This crypto key is a $@.", source.getNode(),
  "hard-coded constant"
