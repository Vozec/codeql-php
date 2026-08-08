/**
 * @name Unsafe deserialization
 * @description User input reaches a deserialization call, enabling Unsafe deserialization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id php/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
private import codeql.php.ast.internal.TreeSitter as TS

/**
 * Holds if `c` is `unserialize($x, ['allowed_classes' => false])` (or `=> []`) — the second argument
 * disables object instantiation, so the call returns DATA only and is NOT a POP-chain / object-injection
 * sink. The key and value are matched in the SAME array element, so `['allowed_classes' => 'Foo']` (a real
 * class allow-list) and `['allowed_classes' => true]` (allow ALL — still unsafe) stay sinks.
 */
private predicate safeDeserialization(FunctionCall c) {
  c.getName() = "unserialize" and
  exists(TS::Php::ArrayElementInitializer el, TS::Php::String key |
    // DIRECT element of the top-level options array — a nested `['options'=>['allowed_classes'=>false]]`
    // is ignored by PHP (top-level `allowed_classes` defaults to true), so it must NOT clear the sink.
    el = c.getArgument(1).(TS::Php::ArrayCreationExpression).getChild(_) and
    key = el.getChild(_) and
    key.getChild(_).(TS::Php::StringContent).getValue() = "allowed_classes"
  |
    exists(TS::Php::Boolean b | b = el.getChild(_) and b.getValue().toLowerCase() = "false")
    or
    exists(TS::Php::ArrayCreationExpression empty | empty = el.getChild(_) and not exists(empty.getChild(_)))
  )
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    n.(Sink).getKind() = "unsafe deserialization" and
    not exists(FunctionCall c | safeDeserialization(c) and n.asExpr() = c.getArgument(0))
  }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or n.(KindSanitizer).getKind() = "unsafe deserialization" }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This deserialization call depends on a $@.", source.getNode(),
  "user-provided value"
