/**
 * @name Stored (second-order) reflected XSS
 * @description User input persisted to an option/meta/transient store and later echoed into a page without
 *              HTML-escaping. The store key is proven to be written from user input elsewhere, so the read
 *              is a genuine second-order source (CWE-79, stored XSS).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id php/stored-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
import codeql.php.security.ModelExtensions
import codeql.php.security.StoredSources

/**
 * Remote input reaching the value written to a store, with the XSS barrier set — so an ESCAPE-ON-WRITE
 * (`update_option('bio', htmlspecialchars($_POST['bio']))`) neutralises the value and the key is NOT
 * XSS-writable. This is a SEPARATE write config from StoredInjection's (which uses only kind-agnostic
 * numeric barriers): an HTML escaper makes a value XSS-safe but not SQL/code-safe.
 */
private module XssWriteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { exists(Expr v | storeWrite(_, _, v) and n.asExpr() = v) }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or n instanceof XssSanitizer }
}

private module XssWriteFlow = TaintTracking::Global<XssWriteConfig>;

/** A store key proven to be written from UN-HTML-ESCAPED user input somewhere in the codebase. */
private predicate xssWritableKey(string key) {
  exists(DataFlow::Node vn, Expr v |
    storeWrite(_, key, v) and vn.asExpr() = v and XssWriteFlow::flowTo(vn)
  )
}

/**
 * A read of a store key written from un-escaped user input — a stored second-order XSS source. Not a
 * `RemoteFlowSource`, so it stays out of the first-order XSS query (no flood); feeds only this query.
 */
class StoredXssSource extends DataFlow::Node {
  StoredXssSource() {
    exists(Call r, string key | storeRead(r, key) and xssWritableKey(key) and this.asExpr() = r)
  }
}

/** Stored value flowing into a reflected-XSS output sink, with the HTML-escaper barrier (escape-on-output). */
module StoredXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof StoredXssSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "reflected XSS" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or n instanceof XssSanitizer }
}

module StoredXssFlow = TaintTracking::Global<StoredXssConfig>;

import StoredXssFlow::PathGraph

from StoredXssFlow::PathNode source, StoredXssFlow::PathNode sink
where StoredXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This page output depends on a value read from a store that is $@.", source.getNode(),
  "written from user input in another request"
