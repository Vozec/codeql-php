/**
 * @name Variable injection (mass assignment via extract)
 * @description Passing request-controlled data to `extract()` (or an equivalent) creates local variables
 *              from ATTACKER-controlled keys, overwriting existing variables (`$is_admin`, `$authenticated`,
 *              config, an object handle) — a mass-assignment / authorization-bypass primitive (CWE-621).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id php/variable-injection
 * @tags security
 *       external/cwe/cwe-621
 *       external/cwe/cwe-915
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
private import codeql.php.ast.internal.TreeSitter as TS

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    n.(Sink).getKind() = "variable injection"
    or
    // `$$name = …` / `${$name} = …` — a variable-VARIABLE write whose NAME is attacker-controlled lets the
    // attacker choose which existing variable to overwrite (`$is_admin`, an object handle, config) — the
    // same mass-assignment primitive as `extract()` (CWE-621). The sink is the inner name expression.
    exists(TS::Php::DynamicVariableName dvn |
      dvn = any(AssignExpr a).getLhs() and n.asExpr() = dvn.getChild()
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    n instanceof Sanitizer or n.(KindSanitizer).getKind() = "variable injection"
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This extract()/mass-assignment turns a $@ into local variable names, overwriting existing variables.",
  source.getNode(), "user-provided value"
