/**
 * @name Dangerous function use (semgrep-audit parity)
 * @description Flags calls to dangerous/audit-worthy built-in functions, mirroring semgrep's
 *              presence-based PHP audit rules (eval-use, phpinfo-use, wp-*-audit, ...).
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id php/semgrep-audit
 * @tags audit
 */

import codeql.php.AST
import codeql.php.ast.internal.TreeSitter

/** Maps a banned/audit-worthy function name to the semgrep rule id it corresponds to. */
private predicate auditFunction(string name, string ruleId) {
  // lang
  name = "assert" and ruleId = "assert-use-audit"
  or
  name = "eval" and ruleId = "eval-use"
  or
  name = "phpinfo" and ruleId = "phpinfo-use"
  or
  name = "unlink" and ruleId = "unlink-use"
  or
  name = "unserialize" and ruleId = "unserialize-use"
  or
  name = ["exec", "system", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"] and
  ruleId = "exec-use"
  or
  name = ["ftp_connect", "ftp_ssl_connect", "ftp_login"] and ruleId = "ftp-use"
  or
  name =
    [
      "mcrypt_encrypt", "mcrypt_decrypt", "mcrypt_create_iv", "mcrypt_generic",
      "mdecrypt_generic", "mcrypt_module_open"
    ] and ruleId = "mcrypt-use"
  or
  // WordPress audit (presence-based)
  name = ["assert", "eval", "call_user_func", "call_user_func_array", "create_function"] and
  ruleId = "wp-code-execution-audit"
  or
  name = ["exec", "system", "shell_exec", "passthru", "popen", "proc_open"] and
  ruleId = "wp-command-execution-audit"
  or
  name = ["file", "file_get_contents", "readfile", "fopen", "fread"] and
  ruleId = "wp-file-download-audit"
  or
  name = ["include", "include_once", "require", "require_once", "fread"] and
  ruleId = "wp-file-inclusion-audit"
  or
  name = ["unlink", "wp_delete_file"] and ruleId = "wp-file-manipulation-audit"
  or
  name = "wp_redirect" and ruleId = "wp-open-redirect-audit"
  or
  name = ["unserialize", "maybe_unserialize"] and ruleId = "wp-php-object-injection-audit"
  or
  name =
    [
      "wp_remote_get", "wp_remote_post", "wp_remote_head", "wp_remote_request",
      "wp_safe_remote_get", "wp_safe_remote_post", "wp_safe_remote_head",
      "wp_safe_remote_request", "wp_oembed_get", "vip_safe_wp_remote_get", "download_url"
    ] and ruleId = "wp-ssrf-audit"
  or
  name = ["is_admin", "is_user_logged_in", "current_user_can", "current_user_can_for_blog"] and
  ruleId = "wp-authorisation-checks-audit"
  or
  name = ["check_ajax_referer", "check_admin_referer", "wp_verify_nonce"] and
  ruleId = "wp-csrf-audit"
  or
  name = "add_action" and ruleId = "wp-ajax-no-auth-and-auth-hooks-audit"
}

/** Maps an audit-worthy method name to the semgrep rule id (presence-based). */
private predicate auditMethod(string name, string ruleId) {
  // WordPress $wpdb raw SQL methods (wp-sql-injection-audit): unsafe unless ->prepare() is used.
  name = ["query", "get_var", "get_row", "get_col", "get_results", "replace"] and
  ruleId = "wp-sql-injection-audit"
}

predicate auditFinding(AstNode n, string msg) {
  exists(FunctionCall c, string ruleId |
    auditFunction(c.getName(), ruleId) and n = c and
    msg = "Call to '" + c.getName() + "' (" + ruleId + ")."
  )
  or
  exists(MethodCall c, string ruleId |
    auditMethod(c.getMethodName(), ruleId) and n = c and
    msg = "Call to method '" + c.getMethodName() + "' (" + ruleId + ")."
  )
  or
  // `include`/`require`/`*_once` are language constructs, not function calls.
  (
    n instanceof Php::IncludeExpression or
    n instanceof Php::IncludeOnceExpression or
    n instanceof Php::RequireExpression or
    n instanceof Php::RequireOnceExpression
  ) and
  msg = "File inclusion construct (wp-file-inclusion-audit)."
}

from AstNode n, string msg
where auditFinding(n, msg)
select n, msg
