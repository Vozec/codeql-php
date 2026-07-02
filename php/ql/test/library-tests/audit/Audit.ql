/**
 * @kind table
 * @id php/test/audit
 * @description Semgrep-style presence-based audit rules for dangerous PHP/WordPress constructs.
 */

import codeql.php.AST
import codeql.php.ast.internal.TreeSitter

private predicate auditFunction(string name, string ruleId) {
  name = "eval" and ruleId = "eval-use"
  or name = "phpinfo" and ruleId = "phpinfo-use"
  or name = "unlink" and ruleId = "unlink-use"
  or name = "unserialize" and ruleId = "unserialize-use"
  or name = ["system", "exec", "shell_exec", "passthru"] and ruleId = "exec-use"
  or name = "assert" and ruleId = "assert-use-audit"
  or name = ["mcrypt_encrypt", "mcrypt_decrypt"] and ruleId = "mcrypt-use"
  or name = ["wp_remote_get", "wp_safe_remote_get", "wp_oembed_get"] and ruleId = "wp-ssrf-audit"
  or name = ["is_admin", "current_user_can", "is_user_logged_in"] and ruleId = "wp-authorisation-checks-audit"
  or name = ["check_ajax_referer", "wp_verify_nonce"] and ruleId = "wp-csrf-audit"
}

query predicate audit(int line, string ruleId) {
  exists(FunctionCall c | auditFunction(c.getName(), ruleId) and line = c.getLocation().getStartLine())
  or
  exists(MethodCall c |
    c.getMethodName() = ["query", "get_var", "get_row", "get_results"] and
    ruleId = "wp-sql-injection-audit" and line = c.getLocation().getStartLine()
  )
  or
  exists(AstNode n |
    (
      n instanceof Php::IncludeExpression or n instanceof Php::IncludeOnceExpression or
      n instanceof Php::RequireExpression or n instanceof Php::RequireOnceExpression
    ) and
    ruleId = "wp-file-inclusion-audit" and line = n.getLocation().getStartLine()
  )
}
