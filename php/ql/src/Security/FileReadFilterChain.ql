/**
 * @name Blind file read via PHP filter chains
 * @description A user-controlled path reaches a file-reading function. Because PHP resolves the path
 *              through stream wrappers (`php://filter/...`), an attacker can read arbitrary local files
 *              via an error-based oracle even when the function only returns a hash, metadata, or no
 *              displayed content — so this is exploitable beyond classic path traversal.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id php/file-read-filter-chain
 * @tags security
 *       external/cwe/cwe-073
 *       external/cwe/cwe-022
 */

import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts
import codeql.php.security.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) { n.(Sink).getKind() = "file read" }

  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This file-read path depends on a $@, enabling an arbitrary file read (php://filter chain oracle).",
  source.getNode(), "user-provided value"
