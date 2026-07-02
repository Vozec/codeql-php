/**
 * Instantiation of the shared static-single-assignment (SSA) library for PHP local variables.
 *
 * A source variable is a `$name` scoped to a CFG scope (PHP has no explicit declarations, so a
 * variable is identified by its name within the enclosing function/method/closure/top-level).
 * Writes are the left-hand sides of `=` assignments; every other variable access is a read.
 *
 * Write accesses covered (`isWriteAccess`): plain/augmented/reference assignments, formal
 * parameters, `foreach` bindings, `list()`/`[...]` destructuring, `global`/`static`/`catch`
 * bindings, and element/property updates (which currently re-define the whole root variable —
 * see AUDIT.md §3 A.1: this should be a weak update, not a strong one).
 */

private import codeql.ssa.Ssa as SsaImplCommon
private import codeql.controlflow.BasicBlock as BB
private import codeql.Locations
private import codeql.php.AST
private import codeql.php.ast.internal.TreeSitter
private import codeql.php.controlflow.ControlFlowGraph
private import codeql.php.controlflow.internal.ControlFlowGraphImpl as CfgImpl

/** The PHP control-flow graph, packaged as a `CfgSig` for the SSA and dataflow libraries. */
module Cfg implements BB::CfgSig<Location> {
  class ControlFlowNode = CfgImpl::CfgImpl::Node;

  class BasicBlock = CfgImpl::CfgImpl::BasicBlocks::BasicBlock;

  class EntryBasicBlock = CfgImpl::CfgImpl::BasicBlocks::EntryBasicBlock;

  predicate dominatingEdge = CfgImpl::CfgImpl::BasicBlocks::dominatingEdge/2;
}

/** Holds if the CFG node at index `i` of basic block `bb` is the variable access `va`. */
predicate variableAccessAt(Cfg::BasicBlock bb, int i, VariableAccess va) {
  bb.getNode(i).getAstNode() = va
}

/** Holds if `va` is the name of a formal parameter (a definition at callable entry). */
predicate isParameterName(VariableAccess va) {
  va = any(Php::SimpleParameter p).getName() or
  va = any(Php::VariadicParameter p).getName() or
  va = any(Php::PropertyPromotionParameter p).getName()
}

/** Holds if `t` is a binding target of a `foreach` (the value, key, or a destructuring pattern). */
predicate isForeachBinding(Php::AstNode t) {
  exists(Php::ForeachStatement f, int i | i >= 1 and t = f.getChild(i))
  or
  exists(Php::Pair p | isForeachBinding(p) and t = p.getChild(_))
}

/**
 * Holds if `t` is a destructuring target: a `list()`/`[...]` pattern on the left of an assignment
 * or as a `foreach` binding, including nested patterns.
 */
predicate isDestructuringTarget(Php::ListLiteral t) {
  exists(Php::AssignmentExpression a | a.getLeft() = t)
  or
  isForeachBinding(t)
  or
  exists(Php::ListLiteral outer | isDestructuringTarget(outer) and t = outer.getChild(_))
}

/**
 * Holds if `va` is a write access — every construct that binds or reassigns a variable:
 *  - `$x = ...`, `$x .= ...`, `$x =& ...`
 *  - formal parameters
 *  - `foreach (... as $x)` / `... as $k => $v` / `... as [$a, $b]`
 *  - `list($a, $b) = ...` / `[$a, $b] = ...` (incl. nested)
 *  - `global $x`, `static $x`, `catch (E $x)`
 */
predicate isWriteAccess(VariableAccess va) {
  exists(AssignExpr a | a.getLhs() = va)
  or
  exists(Php::AugmentedAssignmentExpression a | a.getLeft() = va)
  or
  exists(Php::ReferenceAssignmentExpression a | a.getLeft() = va)
  or
  isParameterName(va)
  or
  va = any(Php::GlobalDeclaration g).getChild(_)
  or
  va = any(Php::StaticVariableDeclaration s).getName()
  or
  va = any(Php::CatchClause c).getName()
  or
  isForeachBinding(va)
  or
  exists(Php::ListLiteral l | isDestructuringTarget(l) and va = l.getChild(_))
  or
  // Update of an element/property: `$a[k] = v` or `$o->p = v` redefines the base variable `$a`/`$o`.
  va = updateBaseVariable()
}

/** Holds if `e` is a nested element/property access (`$x[..]`, `$x->p`, `$x?->p`). */
predicate isNestedAccess(Expr e) {
  e instanceof Php::SubscriptExpression or
  e instanceof Php::MemberAccessExpression or
  e instanceof Php::NullsafeMemberAccessExpression
}

/** Gets the root variable of an access chain, recursively (`$o->a[2]->b` -> `$o`). */
VariableAccess rootVariableOfAccess(Expr e) {
  result = e
  or
  result = rootVariableOfAccess(e.(Php::SubscriptExpression).getChild(0))
  or
  result = rootVariableOfAccess(e.(Php::MemberAccessExpression).getObject())
  or
  result = rootVariableOfAccess(e.(Php::NullsafeMemberAccessExpression).getObject())
}

/**
 * Gets the root variable updated by an element/property assignment, at any depth
 * (`$a[k] = v`, `$o->p = v`, `$o->a[2]->b = v` all update `$a`/`$o`). Field-insensitive: writing to
 * any part of the container re-defines the whole root variable (recall-first).
 */
VariableAccess updateBaseVariable() {
  exists(AssignExpr a | isNestedAccess(a.getLhs()) and result = rootVariableOfAccess(a.getLhs()))
}

private newtype TLocalVariable =
  MkLocalVariable(CfgScope scope, string name) {
    exists(Cfg::BasicBlock bb, int i, VariableAccess va |
      variableAccessAt(bb, i, va) and bb.getScope() = scope and name = va.getName()
    )
  }

/** A PHP local variable, identified by its name within a CFG scope. */
class LocalVariable extends TLocalVariable {
  /** Gets the variable name (without the leading `$`). */
  string getName() { this = MkLocalVariable(_, result) }

  /** Gets the CFG scope this variable belongs to. */
  CfgScope getScope() { this = MkLocalVariable(result, _) }

  /** Gets a textual representation of this variable. */
  string toString() { result = "$" + this.getName() }

  /** Gets the location of a representative access to this variable. */
  Location getLocation() {
    result =
      min(VariableAccess va |
        va.getName() = this.getName() and
        exists(Cfg::BasicBlock bb, int i |
          variableAccessAt(bb, i, va) and bb.getScope() = this.getScope()
        )
      |
        va order by va.getLocation().getStartLine(), va.getLocation().getStartColumn()
      ).getLocation()
  }
}

module SsaInput implements SsaImplCommon::InputSig<Location, Cfg::BasicBlock> {
  class SourceVariable = LocalVariable;

  predicate variableWrite(Cfg::BasicBlock bb, int i, SourceVariable v, boolean certain) {
    exists(VariableAccess va |
      variableAccessAt(bb, i, va) and
      isWriteAccess(va) and
      v = MkLocalVariable(bb.getScope(), va.getName()) and
      // Writes inside a conditional branch are uncertain, so a reassignment in one branch does not
      // shadow a (possibly tainted) assignment in a sibling branch (the linearised CFG would
      // otherwise sequence them). This preserves taint across `if`/`switch`/`match` branches.
      (if inConditionalBranch(va) then certain = false else certain = true)
    )
  }

  /** Holds if `va` occurs inside a conditional branch body (`if`/`elseif`/`else`/`case`/`match` arm). */
  private predicate inConditionalBranch(VariableAccess va) {
    exists(Php::AstNode anc | anc = va.(Php::AstNode).getParent+() |
      anc instanceof Php::IfStatement or
      anc instanceof Php::ElseClause or
      anc instanceof Php::ElseIfClause or
      anc instanceof Php::CaseStatement or
      anc instanceof Php::DefaultStatement or
      anc instanceof Php::MatchConditionalExpression
    )
  }

  predicate variableRead(Cfg::BasicBlock bb, int i, SourceVariable v, boolean certain) {
    exists(VariableAccess va |
      variableAccessAt(bb, i, va) and
      not isWriteAccess(va) and
      v = MkLocalVariable(bb.getScope(), va.getName()) and
      certain = true
    )
  }
}

import SsaImplCommon::Make<Location, Cfg, SsaInput> as Impl

class Definition = Impl::Definition;
