/**
 * Public data-flow node API for PHP, layered on the shared data-flow engine.
 * (This is the "real engine" instantiation; the older hand-rolled TaintTracking is separate.)
 */

private import codeql.php.AST
private import codeql.php.controlflow.ControlFlowGraph as Cfg
private import DataFlowPrivate

/** A node in the data-flow graph. */
class Node extends TNode {
  /** Gets a textual representation of this node. */
  string toString() { result = "node" }

  /** Gets the location of this node. */
  Location getLocation() { none() }

  /** Gets the expression this node corresponds to, if any. */
  Expr asExpr() { none() }

  /** Gets the AST node this data-flow node corresponds to (including non-expression wrappers). */
  AstNode getAstNode() { none() }

  /** Gets the control-flow node backing this data-flow node, if any. */
  Cfg::CfgNode getCfgNode() { none() }
}

/** A data-flow node backed by a control-flow node (an evaluated expression or parameter). */
class ExprNode extends Node, TExprNode {
  Cfg::CfgNode n;

  ExprNode() { this = TExprNode(n) }

  override string toString() { result = n.toString() }

  override Location getLocation() { result = n.getLocation() }

  override Cfg::CfgNode getCfgNode() { result = n }

  override Expr asExpr() { result = n.getAstNode() }

  override AstNode getAstNode() { result = n.getAstNode() }
}

/** Gets the data-flow node corresponding to control-flow node `n`. */
Node exprNode(Cfg::CfgNode n) { result = TExprNode(n) }

/**
 * A parameter, seen as a data-flow node: a positional formal parameter (backed by its CFG node) or
 * the synthetic `$this` parameter (position -1) of a method.
 */
class ParameterNode extends Node {
  ParameterNode() {
    this.getCfgNode() = any(DataFlowCallable c).getParameterCfgNode(_)
    or
    this instanceof ThisParameterNode
  }

  /** Holds if this node is the `pos`th parameter of callable `c` (`pos = -1` is `$this`). */
  predicate isParameterOf(DataFlowCallable c, ParameterPosition pos) {
    this.getCfgNode() = c.getParameterCfgNode(pos)
    or
    pos = -1 and c = this.(ThisParameterNode).getMethod()
  }
}

/** A call, seen as a data-flow node. */
class CallNode extends ExprNode {
  CallNode() { this.getCfgNode() instanceof DataFlowCall }

  DataFlowCall getCall() { result = this.getCfgNode() }
}

/** An argument passed to a call, seen as a data-flow node. */
class ArgumentNode extends ExprNode {
  ArgumentNode() {
    exists(DataFlowCall call, ArgumentPosition pos | this.getCfgNode() = call.getArgumentCfgNode(pos))
  }

  /** Holds if this node is the `pos`th argument of call `call`. */
  predicate argumentOf(DataFlowCall call, ArgumentPosition pos) {
    this.getCfgNode() = call.getArgumentCfgNode(pos)
  }
}

/** A content set (a single content for now). */
class ContentSet instanceof Content {
  Content getAStoreContent() { result = this }

  Content getAReadContent() { result = this }

  string toString() { result = super.toString() }
}
