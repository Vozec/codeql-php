/**
 * @name Open redirect
 * @description User input reaches a HTTP header, enabling Open redirect.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id php/open-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources
private import codeql.php.ast.internal.TreeSitter as TS

/**
 * Holds if constant URL prefix `s` PINS the destination host: it contains `scheme://host` terminated by
 * `/`, `?` or `#`, so anything appended lands in the path/query/fragment, not the host. The terminator is
 * required — `"https://good.com".$x` (x=".evil.com/") yields `good.com.evil.com` and must NOT be cleared.
 * `:` is kept in the host run so a host WITH A PORT (`https://intranet:8443/…`) still pins.
 */
bindingset[s]
private predicate pinsHost(string s) {
  s.regexpMatch("(?s).*https?://[A-Za-z0-9._~%:-]+[/?#].*")
}

/**
 * Holds when `n` is user input appended to a fixed `scheme://host/` base, so it controls only the path —
 * not an open redirect. Two syntaxes:
 *  - concatenation: `header("Location: https://site.tld/" . $userPath)`;
 *  - interpolation: `header("Location: https://site.tld/{$userPath}")` — the constant text before the
 *    interpolation must pin the host with NO earlier interpolation (else the host itself is dynamic).
 * A *constant* scheme+host is required, so a bare `"Location: "` prefix or a spoofable `$_SERVER['HTTP_HOST']`
 * host is NOT cleared.
 */
private predicate hostPinnedConcatOperand(DataFlow::Node n) {
  exists(ConcatExpr ce | ce.getRightOperand() = n.asExpr() and pinsHost(ce.getLeftOperand().(StringLiteral).getValue()))
  or
  exists(TS::Php::EncapsedString enc, int i, int j |
    n.asExpr() = enc.getChild(i) and
    j < i and
    pinsHost(enc.getChild(j).(TS::Php::StringContent).getValue()) and
    // no interpolated expression sits between the pinning constant and `n` — otherwise the host is dynamic.
    not exists(int k, TS::Php::AstNode mid |
      mid = enc.getChild(k) and j < k and k < i and not mid instanceof TS::Php::StringContent
    )
  )
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "open redirect" }

  predicate isBarrier(DataFlow::Node n) {
    n instanceof Sanitizer
    or
    n.(KindSanitizer).getKind() = "open redirect"
    or
    hostPinnedConcatOperand(n)
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This HTTP header depends on a $@.", source.getNode(),
  "user-provided value"
