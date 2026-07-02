/**
 * Provides the PHP-specific `InputSig` module used to instantiate the shared data-flow engine.
 */

private import codeql.dataflow.DataFlow
private import codeql.Locations

module PhpDataFlow implements InputSig<Location> {
  import DataFlowPrivate as Private
  import DataFlowPublic
  import Private

  predicate neverSkipInPathGraph = Private::neverSkipInPathGraph/1;
}
