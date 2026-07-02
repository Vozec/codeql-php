/**
 * @name Loose comparison of a hash or secret (type juggling)
 * @description Comparing a hash/secret with `==`/`!=` (instead of `===`/`hash_equals`) is subject to
 *              PHP type juggling (`"0e123" == "0e456"` is true), enabling authentication bypass.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id php/type-juggling
 * @tags security external/cwe/cwe-697 external/cwe/cwe-259
 */

import codeql.php.AST

/** A function whose result is a hash/digest that must be compared in constant time / strictly. */
private predicate hashFunction(string name) {
  name = ["md5", "sha1", "hash", "crypt", "hash_hmac", "password_hash", "hash_pbkdf2", "bin2hex"]
}

/** Holds if `e` is a hash-function result or a secret-looking variable/property. */
private predicate sensitive(Expr e) {
  exists(FunctionCall c | c = e and hashFunction(c.getName()))
  or
  exists(string n |
    n = [e.(VariableAccess).getName(), e.(FieldAccess).getFieldName()] and
    n.toLowerCase().regexpMatch(".*(pass|pwd|hash|token|secret|signature|hmac|digest|nonce).*")
  )
}

from ComparisonExpr b
where
  b.getOperator() = ["==", "!="] and
  (sensitive(b.getLeftOperand()) or sensitive(b.getRightOperand()))
select b,
  "Loose comparison ('" + b.getOperator() +
    "') of a hash/secret is subject to type juggling; use '===' or hash_equals()."
