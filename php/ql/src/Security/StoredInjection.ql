/**
 * @name Stored (second-order) injection
 * @description User input persisted to an option/meta/transient store and later read back into a
 *              deserialization, code-execution, template, or SQL sink. The store key is proven to be
 *              written from user input elsewhere, so the read is a genuine second-order source.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id php/stored-injection
 * @tags security
 *       external/cwe/cwe-502
 *       external/cwe/cwe-094
 *       external/cwe/cwe-089
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

/** The constant string value of `e` if it is a string literal (single- or double-quoted). */
private string keyString(Expr e) { result = e.(StringLiteral).getValue() }

/**
 * A key-value store WRITE `fn(...)` whose stored VALUE is `value` and whose constant KEY is `key`.
 * Only the WordPress option / metadata / transient setters — all take a constant string key.
 */
private predicate storeWrite(FunctionCall w, string key, Expr value) {
  exists(string fn | fn = w.getName() |
    fn = ["update_option", "add_option", "update_site_option"] and
    key = keyString(w.getArgument(0)) and
    value = w.getArgument(1)
    or
    fn = ["update_post_meta", "update_user_meta", "update_term_meta"] and
    key = keyString(w.getArgument(1)) and
    value = w.getArgument(2)
    or
    fn = ["set_transient", "set_site_transient"] and
    key = keyString(w.getArgument(0)) and
    value = w.getArgument(1)
  )
}

/** A key-value store READ `fn(...)` returning the value stored at constant `key`. */
private predicate storeRead(FunctionCall r, string key) {
  exists(string fn | fn = r.getName() |
    fn = ["get_option", "get_site_option"] and key = keyString(r.getArgument(0))
    or
    fn = ["get_post_meta", "get_user_meta", "get_term_meta"] and key = keyString(r.getArgument(1))
    or
    fn = ["get_transient", "get_site_transient"] and key = keyString(r.getArgument(0))
  )
}

/** Remote input reaching the value written to a key-value store. */
private module WriteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { exists(Expr v | storeWrite(_, _, v) and n.asExpr() = v) }
}

private module WriteFlow = TaintTracking::Global<WriteConfig>;

/** A store key that is PROVEN to be written from user input somewhere in the codebase. */
private predicate userWritableKey(string key) {
  exists(DataFlow::Node vn, Expr v |
    storeWrite(_, key, v) and vn.asExpr() = v and WriteFlow::flowTo(vn)
  )
}

/**
 * A read of a store key that is written from user input elsewhere — a stored (second-order) source.
 * Deliberately NOT a `RemoteFlowSource`: it stays out of the first-order queries (no XSS/SSRF flood)
 * and feeds only this dedicated stored-injection query.
 */
class StoredSource extends DataFlow::Node {
  StoredSource() {
    exists(FunctionCall r, string key |
      storeRead(r, key) and userWritableKey(key) and this.asExpr() = r
    )
  }
}

/** Stored value flowing into a high-severity execution sink. */
module StoredConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof StoredSource }

  predicate isSink(DataFlow::Node n) {
    n.(Sink).getKind() =
      ["unsafe deserialization", "code injection", "template injection", "SQL injection"]
  }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module StoredFlow = TaintTracking::Global<StoredConfig>;

import StoredFlow::PathGraph

from StoredFlow::PathNode source, StoredFlow::PathNode sink
where StoredFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This sink executes a value read from a store that is $@.", source.getNode(),
  "written from user input in another request"
