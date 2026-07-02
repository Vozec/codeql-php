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
class WhileStmt extends Stmt instanceof Php::WhileStatement { }

/** A `foreach` statement. */
class ForeachStmt extends Stmt instanceof Php::ForeachStatement {
  /** Gets the loop body. */
  AstNode getBody() { result = super.getBody() }
}
