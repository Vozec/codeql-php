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

/** A string literal's value with whitespace stripped and lower-cased (for header-name matching). */
private string normStr(AstNode e) {
  result =
    [
      e.(Php::String).getChild(_).(Php::StringContent).getValue(),
      // double-quoted strings without interpolation are `EncapsedString` nodes
      e.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue()
    ].regexpReplaceAll("\\s+", "").toLowerCase()
}

/** A `'Access-Control-Allow-Origin' => '*'` array element (case/whitespace-insensitive). */
private predicate permissiveCorsElement(Php::ArrayElementInitializer el) {
  normStr(el.getChild(0)) = "access-control-allow-origin" and
  normStr(el.getChild(1)) = "*"
}

/**
 * Symfony permissive-CORS misconfiguration: a wildcard `Access-Control-Allow-Origin: *`. Precise —
 * only on a `*Response` constructor argument or a `->headers->set(...)`, and only for value `*`, so a
 * specific origin or a non-Response class does not fire.
 */
private predicate corsFinding(AstNode n) {
  exists(NewExpr ne, Php::ArrayElementInitializer el |
    ne.getClassName().toLowerCase().matches("%response") and
    el.(Php::AstNode).getParent+() = ne and
    permissiveCorsElement(el) and
    n = el
  )
  or
  exists(MethodCall c |
    c.getMethodName() = "set" and
    c.getReceiver().(FieldAccess).getFieldName() = "headers" and
    normStr(c.getArgument(0)) = "access-control-allow-origin" and
    normStr(c.getArgument(1)) = "*" and
    n = c
  )
  or
  // `header("Access-Control-Allow-Origin: *")` — the raw-header form (php-permissive-cors). Exactly
  // `*`, so `header("…: *something*")` or a different header does not fire.
  exists(FunctionCall c |
    c.getName().toLowerCase() = "header" and
    normStr(c.getArgument(0)) = "access-control-allow-origin:*" and
    n = c
  )
}

/** A value that disables CSRF: the literal `false`, or a variable (which may hold `false`). */
private predicate csrfDisabledValue(AstNode v) {
  v.(Php::Boolean).getValue().toLowerCase() = "false"
  or
  v instanceof Php::VariableName
}

/**
 * `'csrf_protection' => false` in a Symfony config array — but NOT `=> true`/`=> null`, and NOT under
 * `prependExtensionConfig('something_else', …)`/`loadFromExtension` for a non-`framework` extension.
 */
private predicate csrfFinding(AstNode n) {
  exists(Php::ArrayElementInitializer el |
    normStr(el.getChild(0)) = "csrf_protection" and
    csrfDisabledValue(el.getChild(1)) and
    not exists(MethodCall c |
      c.getMethodName() = ["prependExtensionConfig", "loadFromExtension"] and
      el.(Php::AstNode).getParent+() = c and
      normStr(c.getArgument(0)) != "framework"
    ) and
    n = el
  )
}

/**
 * `$this->redirect(<non-literal>)` — a redirect to a computed target (variable, concatenation,
 * interpolation). Precise: a plain string-literal URL, `redirectToRoute(...)`, or `redirect()` with no
 * argument does NOT fire.
 */
private predicate nonLiteralRedirect(AstNode n) {
  exists(MethodCall c |
    c.getMethodName() = "redirect" and
    exists(c.getArgument(0)) and
    not c.getArgument(0) instanceof Php::String and
    n = c
  )
}

/**
 * A broken/weak hash primitive (`md5`/`sha1`) used directly — but NOT as an operand of a comparison
 * (`md5($x) === $h`), which is the type-juggling query's domain (and strict `===` is safe there).
 */
private predicate weakHashFinding(AstNode n) {
  exists(FunctionCall c |
    c.getName() = ["md5", "sha1", "md5_file", "sha1_file", "crypt"] and
    not exists(ComparisonExpr cmp | cmp.getAnOperand() = c) and
    n = c
  )
}

/** `ldap_bind` with no password argument, or a NULL/empty password (anonymous/unauthenticated bind). */
private predicate ldapBindFinding(AstNode n) {
  exists(FunctionCall c |
    c.getName().toLowerCase() = "ldap_bind" and
    (
      not exists(c.getArgument(2)) // no password argument (anonymous bind)
      or
      normStr(c.getArgument(2)) = "" // empty-string password
    ) and
    n = c
  )
}

/** Laravel debug mode enabled in code: `config(['app.debug' => 'true'])` / `putenv("APP_DEBUG=true")`. */
private predicate debugEnabledFinding(AstNode n) {
  exists(Php::ArrayElementInitializer el |
    normStr(el.getChild(0)) = ["app.debug", "app_debug"] and
    normStr(el.getChild(1)) = "true" and
    n = el
  )
  or
  exists(FunctionCall c |
    c.getName().toLowerCase() = "putenv" and
    normStr(c.getArgument(0)) = "app_debug=true" and
    n = c
  )
}

predicate auditFinding(AstNode n, string msg) {
  corsFinding(n) and msg = "Permissive CORS wildcard origin (symfony-permissive-cors)."
  or
  debugEnabledFinding(n) and msg = "Debug mode enabled (laravel-active-debug-code)."
  or
  weakHashFinding(n) and msg = "Weak hash primitive (weak-crypto / md5-used-as-password)."
  or
  ldapBindFinding(n) and msg = "LDAP bind without a password (ldap-bind-without-password)."
  or
  nonLiteralRedirect(n) and msg = "Non-literal redirect target (symfony-non-literal-redirect)."
  or
  csrfFinding(n) and msg = "CSRF protection disabled (symfony-csrf-protection-disabled)."
  or
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
