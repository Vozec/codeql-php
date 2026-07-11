/**
 * @name Insecure direct object reference (IDOR) on a sensitive action
 * @description A request-controlled value selects the resource operated on by a sensitive/state-changing
 *              action (delete/update/role-change), and the action is not protected by any authorization
 *              check. An attacker can act on objects they do not own — broken access control. Numeric
 *              sanitizers (`intval`/`absint`/`is_numeric`) stop injection but NOT IDOR: the value is still
 *              attacker-controlled for resource selection, so it stays tainted here (access-control taint
 *              engine).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id php/idor
 * @tags security
 *       external/cwe/cwe-639
 *       external/cwe/cwe-862
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.security.FlowSources
import codeql.php.security.AccessControl
import codeql.php.security.AccessControlTaint

module IdorCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(Call call, int i |
      sensitiveResourceArg(call, i, _) and
      isUnguardedContext(call) and
      n.asExpr() = call.getArgument(i)
    )
  }
}

// Access-control taint: identical to the standard engine but numeric coercion/validation does NOT sanitize
// (a numeric id is still attacker-chosen), so `delete(intval($_GET['id']))` and `if(is_numeric($id))
// delete($id)` are caught.
module IdorFlow = AcTaintTracking::Global<IdorCfg>;

import IdorFlow::PathGraph

from IdorFlow::PathNode source, IdorFlow::PathNode sink
where IdorFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This resource selector of a sensitive action is a $@ and the action has no authorization check (IDOR).",
  source.getNode(), "user-provided value"
