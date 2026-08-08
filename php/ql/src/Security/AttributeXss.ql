/**
 * @name XSS through a quote-unsafe escaper in an HTML attribute
 * @description A value escaped only by a QUOTE-UNSAFE escaper (`strip_tags`, or `htmlspecialchars`/
 *              `htmlentities` with `ENT_NOQUOTES`) and emitted inside a QUOTED HTML attribute can break out
 *              of the attribute with a `'`/`"` — those escapers leave quotes intact. Such escapers are safe
 *              in HTML *body* context (hence treated as sanitizers by the reflected-XSS query), so this is a
 *              dedicated, attribute-context-only detection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id php/attribute-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
private import codeql.php.ast.internal.TreeSitter as TS

/**
 * Holds if `c` is a QUOTE-UNSAFE HTML escaper: `strip_tags` (removes tags but keeps quotes/entities), or
 * `htmlspecialchars`/`htmlentities` called with `ENT_NOQUOTES` and NOT `ENT_QUOTES`/`ENT_COMPAT` (so no
 * quote is encoded). The default (flag omitted) is quote-SAFE on modern PHP, so it is NOT included here.
 */
private predicate quoteUnsafeEscaper(FunctionCall c) {
  c.getName() = "strip_tags"
  or
  c.getName() = ["htmlspecialchars", "htmlentities"] and
  exists(TS::Php::Name fl | fl.getParent*() = c.getArgument(1) and fl.getValue() = "ENT_NOQUOTES") and
  not exists(TS::Php::Name fl |
    fl.getParent*() = c.getArgument(1) and fl.getValue() = ["ENT_QUOTES", "ENT_COMPAT"]
  )
}

/** The result node of a quote-unsafe escaper — excluded from the XSS barrier set below so flow reaches it. */
private predicate quoteUnsafeEscaperResult(DataFlow::Node n) {
  exists(FunctionCall c | quoteUnsafeEscaper(c) and n.asExpr() = c)
}

/** The XSS barriers EXCEPT quote-unsafe escapers: a quote-SAFE re-escape (`htmlspecialchars` default,
 *  `esc_attr`, …) still neutralises the value, but `strip_tags`/`ENT_NOQUOTES` do not. */
private predicate quoteSafeBarrier(DataFlow::Node n) {
  (n instanceof Sanitizer or n instanceof XssSanitizer) and not quoteUnsafeEscaperResult(n)
}

/** Stage 1: remote input reaches the argument of a quote-unsafe escaper. */
private module RemoteArgCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(FunctionCall c | quoteUnsafeEscaper(c) and n.asExpr() = c.getArgument(0))
  }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer or n instanceof XssSanitizer }
}

private module RemoteArgFlow = TaintTracking::Global<RemoteArgCfg>;

/** A quote-unsafe escaper RESULT whose input came from remote data — the second-stage source. */
private predicate weakEscapedRemoteResult(DataFlow::Node n) {
  exists(FunctionCall c, DataFlow::Node arg |
    quoteUnsafeEscaper(c) and
    n.asExpr() = c and
    arg.asExpr() = c.getArgument(0) and
    RemoteArgFlow::flowTo(arg)
  )
}

/** Gets the rightmost constant-string text of a concatenation subtree (the text emitted last). */
private string rightmostConstText(Expr e) {
  result = e.(StringLiteral).getValue()
  or
  result = rightmostConstText(e.(ConcatExpr).getRightOperand())
}

/** Gets the constant text emitted immediately before `v` in a concatenation (`"…='" . v`). */
private string constEmittedBefore(Expr v) {
  exists(ConcatExpr ce | ce.getRightOperand() = v and result = rightmostConstText(ce.getLeftOperand()))
}

/**
 * Holds if constant `s` leaves an HTML attribute value position OPEN, so whatever follows lands inside an
 * attribute. Two forms:
 *  - inside an unclosed tag at an attribute value: `<a title=`, `<input value='`, `<img src="` — the opening
 *    quote is OPTIONAL because a double-quote written in a double-quoted PHP string (`"<a title=\""`) is an
 *    escape sequence that `getValue()` drops, so `<a title=` is all that remains;
 *  - a bare `…='` / `…="` when the tag open sits in an earlier constant chunk.
 * The `<[^<>]*` run cannot cross a `>` , so a body-text `=` (`<p>Total = 5`) is not matched.
 */
bindingset[s]
private predicate opensAttributeQuote(string s) {
  s.regexpMatch("(?s).*<[a-zA-Z][^<>]*[\\s'\"][a-zA-Z0-9_:-]+\\s*=\\s*[\"']?[^\"'<>]*$")
  or
  s.regexpMatch("(?s).*=\\s*[\"'][^\"'<>]*$")
}

/** Holds if `v` is emitted (echo / print / printf / `<?= ?>`) as HTML output. */
private predicate inHtmlOutput(Expr v) {
  v.(TS::Php::AstNode).getParent*() = any(TS::Php::EchoStatement es).getChild()
  or
  v.(TS::Php::AstNode).getParent*() = any(TS::Php::PrintIntrinsic p).getChild()
  or
  exists(FunctionCall c |
    c.getName() = ["print", "printf", "print_r", "vprintf"] and
    v.(TS::Php::AstNode).getParent*() = c.getAnArgument()
  )
}

/** A value emitted inside a QUOTED HTML attribute — the sink. Handles concatenation (`"…='" . v`) and
 *  string interpolation (`"…='{$v}"`). */
private predicate attributeContextSink(DataFlow::Node n) {
  inHtmlOutput(n.asExpr()) and
  (
    opensAttributeQuote(constEmittedBefore(n.asExpr()))
    or
    exists(TS::Php::EncapsedString enc, int i, int j |
      n.asExpr() = enc.getChild(i) and
      j < i and
      opensAttributeQuote(enc.getChild(j).(TS::Php::StringContent).getValue()) and
      not exists(int k, TS::Php::AstNode mid |
        mid = enc.getChild(k) and j < k and k < i and not mid instanceof TS::Php::StringContent
      )
    )
  )
}

/** Stage 2: the weak-escaped remote value flows to a quoted-attribute output, with a quote-SAFE re-escape
 *  (but not the weak escaper itself) still able to neutralise it. */
module AttrXssCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { weakEscapedRemoteResult(n) }

  predicate isSink(DataFlow::Node n) { attributeContextSink(n) }

  predicate isBarrier(DataFlow::Node n) { quoteSafeBarrier(n) }
}

module AttrXssFlow = TaintTracking::Global<AttrXssCfg>;

import AttrXssFlow::PathGraph

from AttrXssFlow::PathNode source, AttrXssFlow::PathNode sink
where AttrXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This value is escaped only by a quote-unsafe escaper ($@) and emitted inside a quoted HTML attribute, so it can break out of the attribute.",
  source.getNode(), "strip_tags / ENT_NOQUOTES"
