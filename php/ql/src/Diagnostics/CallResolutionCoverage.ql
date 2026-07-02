/**
 * @name Call-graph resolution coverage
 * @description Diagnostic metrics for how precisely calls are resolved: type-based dispatch vs
 *              name-based fallback. Higher type-based ratio = more precise analysis.
 * @kind metric
 * @metricType project
 * @id php/diagnostics/call-resolution-coverage
 * @tags diagnostics meta
 */

import codeql.php.AST
import codeql.php.dataflow.internal.TypeInference as TI

private int countMethodCalls() { result = count(MethodCall mc) }

private int countTypedMethodCalls() { result = count(MethodCall mc | TI::hasInferredReceiver(mc)) }

private int countStaticCalls() { result = count(StaticMethodCall sc) }

private int countTypedStaticCalls() {
  result = count(StaticMethodCall sc | exists(TI::staticInferredMethod(sc)))
}

from string metric, int value
where
  metric = "method calls (total)" and value = countMethodCalls()
  or
  metric = "method calls type-resolved" and value = countTypedMethodCalls()
  or
  metric = "static calls (total)" and value = countStaticCalls()
  or
  metric = "static calls type-resolved" and value = countTypedStaticCalls()
  or
  metric = "method type-resolution %" and
  countMethodCalls() > 0 and
  value = countTypedMethodCalls() * 100 / countMethodCalls()
select metric, value
