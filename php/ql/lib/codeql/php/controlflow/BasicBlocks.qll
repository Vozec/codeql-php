/** Provides classes representing basic blocks of the PHP control-flow graph. */

private import codeql.php.controlflow.ControlFlowGraph
private import internal.ControlFlowGraphImpl as Impl

/** A basic block: a maximal straight-line sequence of control-flow nodes. */
class BasicBlock extends Impl::CfgImpl::BasicBlocks::BasicBlock {
  /** Gets an immediate successor basic block. */
  BasicBlock getASuccessor() { result = super.getASuccessor() }

  /** Gets an immediate predecessor basic block. */
  BasicBlock getAPredecessor() { result = super.getAPredecessor() }
}
