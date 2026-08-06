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
 * Holds if `e` is a BENIGN constant operand — a loose comparison of a sensitive value against it does NOT
 * type-juggle, so it must not be reported (the dominant FP at @precision high). Benign:
 *  - a string literal that is neither a PHP "magic-hash" form (`0e123…`) nor a numeric string
 *    (`$hash_algo == 'sha256'`);
 *  - a NON-ZERO integer/float literal (`$passes == 3` — a hash/secret can't equal a fixed non-zero number
 *    via juggling; only `== 0` is the magic-hash trap);
 *  - the boolean `true`.
 * The juggle-exploitable forms — `0`, `0.0`, `'0'`, `''`, `false`, `null`, magic-hash strings — stay reportable.
 */
private predicate benignConstStr(Expr e) {
  (e instanceof TS::Php::String or e instanceof TS::Php::EncapsedString) and
  not exists(string v |
    v = e.(TS::Php::String).getChild(_).(TS::Php::StringContent).getValue() or
    v = e.(TS::Php::EncapsedString).getChild(_).(TS::Php::StringContent).getValue()
  |
    v.regexpMatch("(?i)0+e[0-9]+") or v.regexpMatch("[0-9]+([.][0-9]+)?")
  )
  or
  // a non-zero integer / float literal
  exists(string v | v = e.(TS::Php::Integer).getValue() or v = e.(TS::Php::Float).getValue() |
    not v.regexpMatch("0+([.]0+)?")
  )
  or
  // the boolean `true` (comparisons against `false`/`null` stay reportable)
  e.(TS::Php::Boolean).getValue().toLowerCase() = "true"
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
