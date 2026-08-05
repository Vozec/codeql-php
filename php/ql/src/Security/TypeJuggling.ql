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
private import codeql.php.ast.internal.TreeSitter as TS

/** A function whose result is a hash/digest that must be compared in constant time / strictly. */
private predicate hashFunction(string name) {
  name = ["md5", "sha1", "hash", "crypt", "hash_hmac", "password_hash", "hash_pbkdf2", "bin2hex"]
}

/**
 * Holds if `e` is a BENIGN constant string operand: a string literal whose text is neither a PHP
 * "magic-hash" form (`0e123…`, which juggles to 0) nor a numeric string. A loose comparison of a
 * sensitive value against such a constant (`$hash_algo == 'sha256'`, `$token == ''`) is an ordinary
 * string equality that does NOT type-juggle, so it must not be reported (the dominant FP at @precision
 * high). A magic-hash/numeric literal (`== '0e830400'`, `== '0'`) stays reportable.
 */
private predicate benignConstStr(Expr e) {
  (e instanceof TS::Php::String or e instanceof TS::Php::EncapsedString) and
  not exists(string v |
    v = e.(TS::Php::String).getChild(_).(TS::Php::StringContent).getValue() or
    v = e.(TS::Php::EncapsedString).getChild(_).(TS::Php::StringContent).getValue()
  |
    v.regexpMatch("(?i)0+e[0-9]+") or v.regexpMatch("[0-9]+([.][0-9]+)?")
  )
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
  (
    sensitive(b.getLeftOperand()) and not benignConstStr(b.getRightOperand())
    or
    sensitive(b.getRightOperand()) and not benignConstStr(b.getLeftOperand())
  )
select b,
  "Loose comparison ('" + b.getOperator() +
    "') of a hash/secret is subject to type juggling; use '===' or hash_equals()."
