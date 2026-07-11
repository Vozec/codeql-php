/**
 * A taint-tracking variant for ACCESS-CONTROL queries (IDOR / broken access control).
 *
 * The standard PHP taint engine treats numeric coercion (`intval`/`absint`/`(int)`) and numeric
 * VALIDATION guards (`is_numeric`/`is_int`/`ctype_digit`) as sanitizers — correct for INJECTION (a numeric
 * value can't carry SQL/XSS), but WRONG for IDOR: `wp_delete_post(intval($_GET['id']))` and
 * `if (is_numeric($id)) wp_delete_post($id)` are still attacker-controlled resource selection. This variant
 * removes exactly those numeric barriers (and adds the coercion as a step) so the resource id keeps
 * flowing, while leaving every other sanitizer/step identical to the standard engine.
 *
 * Use `AcTaintTracking::Global<Cfg>` instead of `TaintTracking::Global<Cfg>` in access-control queries.
 */

private import codeql.Locations
private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.dataflow.internal.DataFlowImplSpecific
private import codeql.php.dataflow.internal.TaintTrackingPrivate as Base
private import codeql.dataflow.TaintTracking
import codeql.php.DataFlow

/** Holds if `n` is a numeric COERCION result (`intval`/`absint`/`floatval` or an `(int)`/`(float)` cast).
 *  For IDOR these must NOT sanitize — the coerced value is still the attacker's chosen id. */
private predicate isNumericCoercion(DataFlow::Node n) {
  exists(CastExpr c | c.getTypeName() = ["int", "integer", "float", "double"] and n.asExpr() = c)
  or
  exists(FunctionCall fc | fc.getName() = ["intval", "absint", "floatval"] and n.asExpr() = fc)
}

/** Holds if `n` is a read sanitized ONLY by a NUMERIC validation guard (`is_numeric`/`is_int`/`ctype_digit`).
 *  Mirrors FlowSources::isGuardedRead but restricted to numeric validators, which don't stop IDOR. */
private predicate isNumericGuardedRead(DataFlow::Node n) {
  exists(Php::IfStatement ifs, FunctionCall g, Expr checked, Expr use |
    g.(Php::AstNode).getParent*() = ifs.getCondition() and
    g.getName() = ["is_numeric", "is_int", "is_integer", "ctype_digit"] and
    checked = g.getAnArgument() and
    use.(Php::AstNode).getParent*() = ifs.getBody() and
    use != checked and
    n.asExpr() = use and
    (
      checked.(VariableAccess).getName() = use.(VariableAccess).getName()
      or
      exists(Php::SubscriptExpression a, Php::SubscriptExpression b |
        a = checked and b = use and
        a.getChild(0).(VariableAccess).getName() = b.getChild(0).(VariableAccess).getName()
      )
    )
  )
}

/** The InputSig for the access-control taint engine: identical to the standard PHP taint engine, except the
 *  numeric coercion/validation barriers are dropped and numeric coercion is made a flow step. */
private module PhpAcTaint implements InputSig<Location, PhpDataFlow> {
  predicate defaultTaintSanitizer(DataFlow::Node node) {
    Base::defaultTaintSanitizer(node) and
    not isNumericCoercion(node) and
    not isNumericGuardedRead(node)
  }

  predicate defaultAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink, string model) {
    Base::defaultAdditionalTaintStep(src, sink, model)
    or
    // carry the value through numeric coercion (intval/(int)/...) — it stays the attacker's chosen id.
    model = "ac-numeric-coercion" and
    (
      exists(CastExpr c |
        c.getTypeName() = ["int", "integer", "float", "double"] and
        src.asExpr() = c.getOperand() and
        sink.asExpr() = c
      )
      or
      exists(FunctionCall fc |
        fc.getName() = ["intval", "absint", "floatval"] and
        src.asExpr() = fc.getAnArgument() and
        sink.asExpr() = fc
      )
    )
  }

  predicate defaultImplicitTaintRead(DataFlow::Node node, DataFlow::ContentSet c) {
    Base::defaultImplicitTaintRead(node, c)
  }

  predicate speculativeTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    Base::speculativeTaintStep(src, sink)
  }
}

/** Access-control taint tracking: `AcTaintTracking::Global<Cfg>`. */
module AcTaintTracking = TaintFlowMake<Location, PhpDataFlow, PhpAcTaint>;
