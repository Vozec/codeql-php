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

/** The constant string value of `e` if it is a string literal (single- or double-quoted). */
private string keyString(Expr e) { result = e.(StringLiteral).getValue() }

/** Holds when `c` is a call to the function/method `name` (`subjectKind` = "function" | "method"). */
private predicate callMatches(Call c, string subjectKind, string name) {
  subjectKind = "function" and c.(FunctionCall).getName() = name
  or
  subjectKind = "method" and c.(MethodCall).getMethodName() = name
}

/** The (possibly composite `scope|name`) constant key of call `c` at `keyArg` / `keyArg2` (-1 = none). */
private string keyOf(Call c, int keyArg, int keyArg2) {
  keyArg2 = -1 and result = keyString(c.getArgument(keyArg))
  or
  keyArg2 >= 0 and
  result = keyString(c.getArgument(keyArg)) + "|" + keyString(c.getArgument(keyArg2))
}

/**
 * A key-value store WRITE whose stored VALUE is `value` and whose constant KEY is `key`. The store APIs
 * are Models-as-Data (`storeWriteModel`), so covering a new store is a data addition, not QL.
 */
private predicate storeWrite(Call w, string key, Expr value) {
  exists(string subj, string name, int keyArg, int keyArg2, int valueArg |
    storeWriteModel(subj, name, keyArg, keyArg2, valueArg) and
    callMatches(w, subj, name) and
    key = keyOf(w, keyArg, keyArg2) and
    value = w.getArgument(valueArg)
  )
}

/** A key-value store READ returning the value stored at constant `key` (`storeReadModel` data). */
private predicate storeRead(Call r, string key) {
  exists(string subj, string name, int keyArg, int keyArg2 |
    storeReadModel(subj, name, keyArg, keyArg2) and
    callMatches(r, subj, name) and
    key = keyOf(r, keyArg, keyArg2)
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
    exists(Call r, string key | storeRead(r, key) and userWritableKey(key) and this.asExpr() = r)
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
