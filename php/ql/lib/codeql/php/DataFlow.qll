/**
 * Provides interprocedural, field-sensitive, path-explaining data-flow analysis for PHP,
 * built on the shared CodeQL data-flow engine.
 */

import codeql.Locations

module DataFlow {
  private import codeql.dataflow.DataFlow
  private import codeql.php.dataflow.internal.DataFlowImplSpecific
  import DataFlowMake<Location, PhpDataFlow>
  import codeql.php.dataflow.internal.DataFlowPublic
}
