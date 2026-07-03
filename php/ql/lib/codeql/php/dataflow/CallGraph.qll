/**
 * Public call-graph resolution API for PHP: which method/function a call dispatches to, resolved by
 * the inferred receiver type (with virtual dispatch) and by name. This exposes the type-inference
 * results without requiring queries to import an internal module.
 */

private import codeql.php.dataflow.internal.TypeInference as TI
import codeql.php.AST

/** Holds if the receiver type of instance-method call `mc` is inferred (type-based dispatch applies). */
predicate hasResolvedReceiver(MethodCall mc) { TI::hasInferredReceiver(mc) }

/** Gets a method that instance-method call `mc` dispatches to, by inferred receiver type. */
Method getInferredTarget(MethodCall mc) { result = TI::inferredMethod(mc) }

/** Holds if the scope class of static-method call `sc` is resolved (type-based dispatch applies). */
predicate hasResolvedStaticTarget(StaticMethodCall sc) { TI::hasInferredStaticTarget(sc) }

/** Gets a method that static-method call `sc` (`C::m`/`self::`/`static::`/`parent::`) dispatches to. */
Method getStaticInferredTarget(StaticMethodCall sc) { result = TI::staticInferredMethod(sc) }
