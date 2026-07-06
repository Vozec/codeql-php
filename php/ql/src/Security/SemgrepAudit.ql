/**
 * @name Dangerous / audit-worthy code shape
 * @description A GENERIC, data-driven audit engine: it reports code shapes described declaratively by
 *              the audit MAD (`auditPresence` / `auditArg` / `auditArrayKV` in `ext/*.audit.model.yml`),
 *              mirroring semgrep's presence/pattern PHP audit rules. Adding a rule is a data row, not QL.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id php/semgrep-audit
 * @tags audit
 */

import codeql.php.AST
import codeql.php.ast.internal.TreeSitter
import codeql.php.security.ModelExtensions

/** The normalised string value of a literal node: string/encapsed content or a boolean token, with
 *  whitespace stripped and lower-cased (so header names / keys / values compare robustly). */
private string norm(AstNode e) {
  result =
    [
      e.(Php::String).getChild(_).(Php::StringContent).getValue(),
      e.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue(),
      e.(Php::Boolean).getValue()
    ].regexpReplaceAll("\\s+", "").toLowerCase()
  or
  // the `null` literal normalises to "null" (so `equals null` can match, e.g. an empty LDAP password)
  e instanceof Php::Null and result = "null"
}

/** Holds if argument/operand node `a` satisfies `op operand` — the fixed matcher vocabulary. */
bindingset[op, operand]
private predicate opMatches(AstNode a, string op, string operand) {
  op = "equals" and norm(a) = operand
  or
  op = "prefix" and norm(a).matches(operand + "%")
  or
  op = "contains" and norm(a).matches("%" + operand + "%")
  or
  op = "nonliteral" and not a instanceof Php::String and not a instanceof Php::EncapsedString
  or
  op = "isvar" and a instanceof Php::VariableName
  or
  // `callto` — the argument is a call to one of the `|`-separated function names, OR a call whose own
  // first argument is such a call (one level of hex/encoding wrapper, e.g. `bin2hex(hash(...))` feeding
  // `base_convert`). The wrapper case is what distinguishes `base_convert(bin2hex(hash(...)))` (flag)
  // from `base_convert(bin2hex(random_bytes(...)))` (clean) without flagging `bin2hex` outright.
  op = "callto" and
  exists(FunctionCall fc | fc = a |
    fc.getName().toLowerCase() = operand.splitAt("|") or
    fc.getArgument(0).(FunctionCall).getName().toLowerCase() = operand.splitAt("|")
  )
}

/** Holds if a sibling value node `v` satisfies `op val` — adds a `falsy` op over `opMatches`. */
bindingset[op, val]
private predicate siblingValueMatches(AstNode v, string op, string val) {
  opMatches(v, op, val)
  or
  // `falsy` — a literal `false` / `null` value (an `env(_, false)` default is intentionally NOT falsy:
  // the runtime env var may set it securely, and the corpus treats it as clean).
  op = "falsy" and norm(v) = ["false", "null"]
}

/** Holds if call `c` satisfies the named `guard` (fixed vocabulary). */
private predicate guardHolds(Expr c, string guard) {
  guard = ""
  or
  guard = "not-comparison" and not exists(ComparisonExpr cmp | cmp.getAnOperand() = c)
}

/** Holds if array element `el` sits in the enclosing `context` (fixed vocabulary). */
private predicate contextHolds(Php::ArrayElementInitializer el, string context) {
  context = ""
  or
  context = "new-response" and
  exists(NewExpr ne | ne.getClassName().toLowerCase().matches("%response") and el.getParent+() = ne)
  or
  context = "framework-ext" and
  not exists(MethodCall c |
    c.getMethodName() = ["prependExtensionConfig", "loadFromExtension"] and
    el.(Php::AstNode).getParent+() = c and
    norm(c.getArgument(0)) != "framework"
  )
}

/** The engine: a finding is any code node matching a declarative audit rule (F1/F2/F3). */
predicate auditFinding(AstNode n, string ruleId) {
  // F1 — presence (function or method), with an optional guard. PHP call names are case-insensitive,
  // so match the lower-cased name against the (lower-case) data.
  exists(string guard |
    exists(FunctionCall c |
      auditPresence("function", c.getName().toLowerCase(), guard, ruleId) and guardHolds(c, guard) and n = c
    )
    or
    exists(MethodCall c |
      auditPresence("method", c.getMethodName().toLowerCase(), guard, ruleId) and guardHolds(c, guard) and n = c
    )
  )
  or
  // F2/F4 — an argument satisfies op/operand (function or method).
  exists(int i, string op, string operand |
    exists(FunctionCall c |
      auditArg("function", c.getName().toLowerCase(), i, op, operand, ruleId) and
      (op = "absent" and not exists(c.getArgument(i)) or opMatches(c.getArgument(i), op, operand)) and
      n = c
    )
    or
    exists(MethodCall c |
      auditArg("method", c.getMethodName().toLowerCase(), i, op, operand, ruleId) and
      (op = "absent" and not exists(c.getArgument(i)) or opMatches(c.getArgument(i), op, operand)) and
      n = c
    )
  )
  or
  // F3 — an array element `key => value` in an enclosing context.
  exists(Php::ArrayElementInitializer el, string kOp, string kPat, string vOp, string vPat, string ctx |
    auditArrayKV(kOp, kPat, vOp, vPat, ctx, ruleId) and
    opMatches(el.getChild(0), kOp, kPat) and
    opMatches(el.getChild(1), vOp, vPat) and
    contextHolds(el, ctx) and
    n = el
  )
  or
  // F5 — flag the `flagKey => *` element when a SIBLING `sibKey => *` in the same array satisfies the
  // value op. For config audits keyed on a neighbouring flag (e.g. flag `'cookie'` when `'http_only'`
  // is false). Only fires when the sibling is present and matching (no absent branch — that would flag
  // every array with the key).
  exists(
    Php::ArrayElementInitializer flagEl, Php::ArrayElementInitializer sibEl, string fKey, string sKey,
    string sOp, string sVal
  |
    auditArraySibling(fKey, sKey, sOp, sVal, ruleId) and
    opMatches(flagEl.getChild(0), "equals", fKey) and
    sibEl.getParent() = flagEl.getParent() and
    opMatches(sibEl.getChild(0), "equals", sKey) and
    siblingValueMatches(sibEl.getChild(1), sOp, sVal) and
    n = flagEl
  )
  or
  // ---- Structural exceptions: shapes with a receiver+multi-arg conjunction that the flat F1/F2/F3
  //      data vocabulary cannot express without becoming a mini-language. Kept minimal (2 shapes).
  //
  // `$response->headers->set('access-control-allow-origin', '*')` — receiver field + two arg matches.
  exists(MethodCall c |
    c.getMethodName() = "set" and
    c.getReceiver().(FieldAccess).getFieldName() = "headers" and
    norm(c.getArgument(0)) = "access-control-allow-origin" and
    norm(c.getArgument(1)) = "*" and
    n = c and
    ruleId = "symfony-permissive-cors"
  )
  or
  // `include`/`require`/`*_once` are language constructs, not calls.
  (
    n instanceof Php::IncludeExpression or
    n instanceof Php::IncludeOnceExpression or
    n instanceof Php::RequireExpression or
    n instanceof Php::RequireOnceExpression
  ) and
  ruleId = "wp-file-inclusion-audit"
  or
  // Backtick shell execution `` `cmd` `` is the ShellCommandExpression operator, not a call.
  n instanceof Php::ShellCommandExpression and
  ruleId = "backticks-use"
}

from AstNode n, string ruleId
where auditFinding(n, ruleId)
select n, "Audit: " + ruleId + "."
