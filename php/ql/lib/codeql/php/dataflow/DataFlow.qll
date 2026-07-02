/**
 * Provides a local data-flow model for PHP.
 *
 * v1 scope: intra-procedural def-use flow. A value assigned to a variable flows to every read of
 * that variable reached by the assignment (computed via SSA). Flow through calls (argument →
 * parameter, return → call) and through data structures is added by the global taint engine
 * (Phase 5).
 */

private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.dataflow.internal.SsaImpl as SsaImpl

/**
 * Holds if `target` (a simple variable) is assigned the value of `rhs`, covering plain (`=`),
 * augmented (`.=`, `+=`, …) and reference (`=&`) assignments.
 */
private predicate simpleAssignment(VariableAccess target, Expr rhs) {
  exists(AssignExpr a | a.getLhs() = target and a.getRhs() = rhs)
  or
  exists(Php::AugmentedAssignmentExpression a | a.getLeft() = target and a.getRight() = rhs)
  or
  exists(Php::ReferenceAssignmentExpression a | a.getLeft() = target and a.getRight() = rhs)
  or
  // Element/property update: `$a[k] = v` / `$o->p = v` taints the whole base variable
  // (field-insensitive, recall-first).
  exists(AssignExpr a |
    (
      target = a.getLhs().(Php::SubscriptExpression).getChild(0) or
      target = a.getLhs().(Php::MemberAccessExpression).getObject()
    ) and
    rhs = a.getRhs()
  )
}

module DataFlow {
  /** A node in the data-flow graph. For now, every expression is a node. */
  class Node instanceof Expr {
    /** Gets a textual representation of this node. */
    string toString() { result = super.toString() }

    /** Gets the location of this node. */
    Location getLocation() { result = super.getLocation() }

    /** Gets the expression this node corresponds to. */
    Expr asExpr() { result = this }
  }

  /**
   * Holds if data flows from `nodeFrom` to `nodeTo` in one local step.
   *
   * The core step is def-use: the right-hand side of `$v = rhs` flows to every read of `$v`
   * that the assignment reaches.
   */
  predicate localFlowStep(Node nodeFrom, Node nodeTo) {
    exists(
      VariableAccess target, Expr rhs, SsaImpl::LocalVariable v, SsaImpl::Definition def,
      SsaImpl::Cfg::BasicBlock bbw, int iw, SsaImpl::Cfg::BasicBlock bbr, int ir
    |
      simpleAssignment(target, rhs) and
      SsaImpl::variableAccessAt(bbw, iw, target) and
      def.definesAt(v, bbw, iw) and
      nodeFrom.asExpr() = rhs and
      SsaImpl::Impl::ssaDefReachesRead(v, def, bbr, ir) and
      SsaImpl::variableAccessAt(bbr, ir, nodeTo.asExpr())
    )
  }

  /** Holds if data flows from `source` to `sink` in zero or more local steps. */
  pragma[inline]
  predicate localFlow(Node source, Node sink) { localFlowStep*(source, sink) }
}
