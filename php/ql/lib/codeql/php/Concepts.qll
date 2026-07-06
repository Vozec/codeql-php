/**
 * Extensible security concepts for PHP.
 *
 * These abstract classes are the extension points of the analysis. To teach the analysis about a
 * new framework, sink, source, sanitizer or taint step, you EITHER:
 *   - subclass one of these in your own `.qll` (QL extension), OR
 *   - add a row to a data-extension `.model.yml` file (data extension — no QL needed).
 *
 * The core queries never need to change when a new framework appears.
 */

private import codeql.util.Unit
private import codeql.php.AST
private import codeql.php.DataFlow

/**
 * A source of remote, attacker-controlled input (request parameters, headers, framework request
 * objects, route parameters, …). Extend this to add new sources.
 */
abstract class RemoteFlowSource extends DataFlow::Node {
  /** Gets a description of the kind of source this is. */
  abstract string getSourceType();
}

/**
 * A sink at which tainted data enables a vulnerability. `getKind()` names the vulnerability class
 * (e.g. `"command injection"`, `"SQL injection"`). Extend this to add new sinks.
 */
abstract class Sink extends DataFlow::Node {
  /** Gets the vulnerability kind of this sink. */
  abstract string getKind();
}

/**
 * A value that stops taint (an output-encoder, escaper, validator, numeric cast, …). Extend this to
 * add new sanitizers.
 */
abstract class Sanitizer extends DataFlow::Node { }

/**
 * A value sanitized for HTML/XSS output ONLY — it strips tags or HTML-encodes, but does NOT neutralise
 * SQL, path, command, … contexts (e.g. WordPress `sanitize_text_field`, which drops tags but leaves
 * quotes intact). It is a barrier for the reflected-XSS query only, so `sanitize_text_field($_GET[..])`
 * reaching `$wpdb->query(...)` is still reported — the sanitize-then-SQLi class (CVE-2024-1071, …).
 */
abstract class XssSanitizer extends DataFlow::Node { }

/**
 * An additional taint-propagation step (through a framework helper, a string/regex function, a
 * custom container, …). Extend this to add new steps.
 */
class AdditionalTaintStep extends Unit {
  /** Holds if taint propagates from `pred` to `succ` through this step. */
  abstract predicate step(DataFlow::Node pred, DataFlow::Node succ);
}

/**
 * A barrier guard: a check that, when it controls a branch, sanitizes a value on that branch
 * (e.g. `if (ctype_alnum($x)) { ... }`, `if (in_array($x, $allow)) { ... }`, `if ($x === 'a')`).
 * Extend this to add new guards.
 */
abstract class SanitizerGuard extends AstNode {
  /** Holds if this guard sanitizes `e` when it evaluates to `branch`. */
  abstract predicate checks(Expr e, boolean branch);
}
