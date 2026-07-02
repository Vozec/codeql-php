private import codeql.Locations
private import codeql.dataflow.TaintTracking
private import DataFlowImplSpecific

module PhpTaintTracking implements InputSig<Location, PhpDataFlow> {
  import TaintTrackingPrivate
}
