/** Provides classes for PHP expressions. */

private import codeql.php.ast.internal.TreeSitter
import codeql.php.ast.AstNode

/** An expression. */
class Expr extends AstNode instanceof Php::Expression {
  override string toString() { result = this.getPrimaryQlClass() }
}

/**
 * An access to a variable, e.g. `$name`.
 *
 * Note the leading `$` is not part of the stored name: `$name` has name `"name"`.
 */
class VariableAccess extends Expr instanceof Php::VariableName {
  /** Gets the variable name without the leading `$`. */
  string getName() { result = super.getChild().getValue() }
}

/** A literal expression (integer, string, boolean, null, float). */
class Literal extends Expr {
  Literal() {
    this instanceof Php::Integer or
    this instanceof Php::String or
    this instanceof Php::Boolean or
    this instanceof Php::Null or
    this instanceof Php::Float or
    this instanceof Php::EncapsedString
  }
}

/** A string literal, either a plain `String` or an interpolated `EncapsedString`. */
class StringLiteral extends Literal {
  StringLiteral() { this instanceof Php::String or this instanceof Php::EncapsedString }

  /** Holds if this string contains interpolation, e.g. `"hi $name"`. */
  predicate isInterpolated() { this instanceof Php::EncapsedString }
}

/** A binary operation, e.g. `$a . $b` or `$x == $y`. */
class BinaryOperation extends Expr instanceof Php::BinaryExpression {
  /** Gets the operator string, e.g. `"."`, `"=="`, `"==="`. */
  string getOperator() { result = super.getOperator() }

  /** Gets the left operand. */
  Expr getLeftOperand() { result = super.getLeft() }

  /** Gets the right operand. */
  Expr getRightOperand() { result = super.getRight().(Expr) }

  /** Gets either operand. */
  Expr getAnOperand() { result = this.getLeftOperand() or result = this.getRightOperand() }
}

/** A string concatenation, `$a . $b`. Taint flows through it. */
class ConcatExpr extends BinaryOperation {
  ConcatExpr() { this.getOperator() = "." }
}

/** A loose or strict comparison (`==`, `===`, `!=`, `!==`). */
class ComparisonExpr extends BinaryOperation {
  ComparisonExpr() { this.getOperator() = ["==", "===", "!=", "!==", "<>"] }

  /** Holds if this is a strict comparison (`===`/`!==`), which does not type-juggle. */
  predicate isStrict() { this.getOperator() = ["===", "!=="] }
}

/** An assignment, `$x = expr`. */
class AssignExpr extends Expr instanceof Php::AssignmentExpression {
  /** Gets the left-hand (target) side. */
  Expr getLhs() { result = super.getLeft().(Expr) }

  /** Gets the right-hand (value) side. */
  Expr getRhs() { result = super.getRight() }
}

/** An array element access, `$a[$k]`. */
class ArrayAccess extends Expr instanceof Php::SubscriptExpression {
  /** Gets the array being indexed. */
  Expr getArray() { result = super.getChild(0) }

  /** Gets the index expression, if present. */
  Expr getIndex() { result = super.getChild(1) }
}

/** A cast expression, e.g. `(int) $x`. */
class CastExpr extends Expr instanceof Php::CastExpression {
  /** Gets the target type name, e.g. `int`. */
  string getTypeName() { result = super.getType().getValue() }

  /** Gets the expression being cast. */
  Expr getOperand() { result = super.getValue().(Expr) }
}
