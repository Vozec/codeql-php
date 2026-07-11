/**
 * @name Missing authorization on a state-changing action
 * @description An attacker-reachable entrypoint (AJAX / admin-post / module controller) performs a
 *              sensitive, state-changing or privilege operation without any authorization (capability)
 *              check in its handler. Reachable at low or no privilege, this is broken access control /
 *              privilege escalation — the dominant WordPress/CMS bounty class. A nonce or `is_admin()`
 *              is authenticity, not authorization, and is deliberately not treated as a guard.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id php/missing-authorization
 * @tags security
 *       external/cwe/cwe-862
 *       external/cwe/cwe-639
 *       external/cwe/cwe-269
 */

import codeql.php.AST
import codeql.php.security.AccessControl

from Entrypoint e, Call action, string category, string priv
where missingAuthorization(e, action, category, priv)
select action,
  "This " + category + " action runs in an " + priv +
    "-reachable handler with no authorization (capability) check — broken access control."
