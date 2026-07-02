/** Provides classes representing the PHP control-flow graph. */

private import codeql.php.AST
private import internal.ControlFlowGraphImpl as Impl
import codeql.controlflow.SuccessorType

/** A scope with its own control-flow graph: a callable body or the file top level. */
class CfgScope = Impl::CfgScope::CfgScope;

/**
 * A control-flow node: a node in the control-flow graph. There is a many-to-one relationship
 * between CFG nodes and AST nodes. Only nodes reachable from an entry point are included.
 */
class CfgNode extends Impl::CfgImpl::Node {
  /** Gets the AST node this control-flow node corresponds to, if any. */
  AstNode getAstNode() { result = super.getAstNode() }

  /** Gets an immediate successor of this node, of any kind. */
  CfgNode getASuccessor() { result = super.getASuccessor() }

  /** Gets an immediate successor of this node reached with successor type `t`. */
  CfgNode getASuccessor(SuccessorType t) { result = super.getASuccessor(t) }

  /** Gets an immediate predecessor of this node. */
  CfgNode getAPredecessor() { result = super.getAPredecessor() }

  /** Gets the CFG scope this node belongs to. */
  CfgScope getScope() { result = super.getScope() }
}

/** The entry node of a CFG scope. */
class EntryNode extends CfgNode instanceof Impl::CfgImpl::EntryNode { }

/** The exit node of a CFG scope. */
class ExitNode extends CfgNode instanceof Impl::CfgImpl::ExitNode { }

/** A control-flow node backed by an AST node. */
class AstCfgNode extends CfgNode {
  AstCfgNode() { exists(super.getAstNode()) }
}
