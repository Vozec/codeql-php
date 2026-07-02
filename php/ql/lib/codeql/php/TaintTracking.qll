/**
 * Provides interprocedural taint-tracking for PHP, built on the shared engine.
 */

import codeql.Locations

module TaintTracking {
  private import codeql.php.dataflow.internal.DataFlowImplSpecific
  private import codeql.php.dataflow.internal.TaintTrackingImplSpecific
  private import codeql.dataflow.TaintTracking
  import TaintFlowMake<Location, PhpDataFlow, PhpTaintTracking>
}
