/**
 * Shared library for STORED (second-order) taint: the key-value store Models-as-Data
 * (`storeWriteModel`/`storeReadModel`) consumed as `storeWrite`/`storeRead`, reused by the
 * `StoredInjection.ql` (exec-kind sinks) and `StoredXss.ql` (reflected-XSS) queries. Each query builds its
 * own write-side barrier (kind-agnostic numeric for exec sinks; `XssSanitizer` for XSS) on top of these.
 */

private import codeql.php.AST
import codeql.php.security.ModelExtensions

/** The constant string value of `e` if it is a string literal (single- or double-quoted). */
private string keyString(Expr e) { result = e.(StringLiteral).getValue() }

/** Holds when `c` is a call to the function/method `name` (`subjectKind` = "function" | "method"). */
predicate storeCallMatches(Call c, string subjectKind, string name) {
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
predicate storeWrite(Call w, string key, Expr value) {
  exists(string subj, string name, int keyArg, int keyArg2, int valueArg |
    storeWriteModel(subj, name, keyArg, keyArg2, valueArg) and
    storeCallMatches(w, subj, name) and
    key = keyOf(w, keyArg, keyArg2) and
    value = w.getArgument(valueArg)
  )
}

/** A key-value store READ returning the value stored at constant `key` (`storeReadModel` data). */
predicate storeRead(Call r, string key) {
  exists(string subj, string name, int keyArg, int keyArg2 |
    storeReadModel(subj, name, keyArg, keyArg2) and
    storeCallMatches(r, subj, name) and
    key = keyOf(r, keyArg, keyArg2)
  )
}
