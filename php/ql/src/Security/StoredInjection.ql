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
import codeql.php.security.ModelExtensions
import codeql.php.security.StoredSources

/** Remote input reaching the value written to a key-value store. */
private module WriteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { exists(Expr v | storeWrite(_, _, v) and n.asExpr() = v) }

  // A key whose write value is coerced to a NUMBER is not a real second-order vector for ANY read-sink
  // kind. The barrier is restricted to kind-AGNOSTIC numeric coercions (scalar-param/settype/filter_var,
  // numeric casts, intval) — NOT the whole `Sanitizer` class: an SQL escaper on the write path must NOT
  // mark the key safe for a code-injection / XSS read (that was a cross-kind false negative).
  predicate isBarrier(DataFlow::Node n) {
    isNumericValueBarrier(n)
    or
    exists(CastExpr c |
      c.getTypeName() = ["int", "integer", "float", "double", "real", "bool", "boolean"] and n.asExpr() = c
    )
    or
    exists(FunctionCall fc |
      fc.getName() = ["intval", "absint", "floatval", "doubleval"] and n.asExpr() = fc
    )
  }
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
    exists(Call r, string key | storeRead(r, key) and userWritableKey(key) and this.asExpr() = r)
  }
}

/** Stored value flowing into a high-severity execution sink. */
module StoredConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof StoredSource }

  predicate isSink(DataFlow::Node n) {
    n.(Sink).getKind() =
      [
        "unsafe deserialization", "code injection", "template injection", "SQL injection",
        // second-order RCE / LFI / SSRF / LDAP: a stored option read into system()/include()/… is the same
        // second-order class; the Sanitizer barrier is already correct for these kinds.
        "command injection", "path traversal", "server-side request forgery", "ldap injection"
      ]
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
