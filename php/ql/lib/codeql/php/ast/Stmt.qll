/** Provides classes for PHP statements. */

private import codeql.php.ast.internal.TreeSitter
import codeql.php.ast.AstNode
import codeql.php.ast.Expr

/** A statement. */
class Stmt extends AstNode instanceof Php::Statement {
  override string toString() { result = this.getPrimaryQlClass() }
}

/** An expression statement, `expr;`. */
class ExprStmt extends Stmt instanceof Php::ExpressionStatement {
  /** Gets the wrapped expression. */
  Expr getExpr() { result = super.getChild() }
}

/** An `echo` statement. */
class EchoStmt extends Stmt instanceof Php::EchoStatement {
  /** Gets an operand printed by this `echo`. */
  Expr getAnOperand() { result = super.getChild().(Expr) }
}

/** A `return` statement. */
class ReturnStmt extends Stmt instanceof Php::ReturnStatement {
  /** Gets the returned expression, if any. */
  Expr getValue() { result = super.getChild() }
}

/** An `if` statement. */
class IfStmt extends Stmt instanceof Php::IfStatement {
  /** Gets the condition expression (unwrapping the surrounding parentheses). */
  Expr getCondition() { result = super.getCondition().getChild() }

  /** Gets the "then" body. */
  AstNode getBody() { result = super.getBody() }
}

/** A `while` statement. */
class WhileStmt extends Stmt instanceof Php::WhileStatement {
  /** Gets the loop condition. */
  Expr getCondition() { result = super.getCondition().(Expr) }

  /** Gets the loop body. */
  AstNode getBody() { result = super.getBody() }
}

/** A `do … while` statement. */
class DoStmt extends Stmt instanceof Php::DoStatement {
  /** Gets the loop condition. */
  Expr getCondition() { result = super.getCondition().(Expr) }

  /** Gets the loop body. */
  AstNode getBody() { result = super.getBody() }
}

/** A `for (init; cond; update) body` statement. */
class ForStmt extends Stmt instanceof Php::ForStatement {
  /** Gets the loop condition, if any. */
  Expr getCondition() { result = super.getCondition().(Expr) }

  /** Gets a body statement. */
  AstNode getBody() { result = super.getBody(_) }
}

/** A `foreach` statement. */
class ForeachStmt extends Stmt instanceof Php::ForeachStatement {
  /** Gets the loop body. */
  AstNode getBody() { result = super.getBody() }
}

/** A `switch` statement. */
class SwitchStmt extends Stmt instanceof Php::SwitchStatement {
  /** Gets the subject expression. */
  Expr getSubject() { result = super.getCondition().(Expr) }

  /** Gets a `case`/`default` arm. */
  AstNode getAnArm() { result = super.getBody().getChild(_) }
}

/** A `try … catch … finally` statement. */
class TryStmt extends Stmt instanceof Php::TryStatement {
  /** Gets the `try` body. */
  AstNode getBody() { result = super.getBody() }

  /** Gets a `catch` clause. */
  CatchClause getACatchClause() { result = super.getChild(_) }
}

/** A `catch (Type $e) { … }` clause. */
class CatchClause extends AstNode instanceof Php::CatchClause {
  /** Gets the caught-exception variable name (without the leading `$`). */
  string getVariableName() { result = super.getName().getChild().getValue() }

  /** Gets the clause body. */
  AstNode getBody() { result = super.getBody() }
}

/** A `break` statement. */
class BreakStmt extends Stmt instanceof Php::BreakStatement { }

/** A `continue` statement. */
class ContinueStmt extends Stmt instanceof Php::ContinueStatement { }
