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

  /** Holds if this string has literal text content (is non-empty). */
  predicate hasContent() {
    exists(this.(Php::String).getChild(_).(Php::StringContent)) or
    exists(this.(Php::EncapsedString).getChild(_).(Php::StringContent))
  }

  /** Holds if this string is a compile-time constant (no interpolated variables). */
  predicate isConstant() {
    this instanceof Php::String
    or
    this instanceof Php::EncapsedString and
    not this.(Php::EncapsedString).getChild(_) instanceof Php::VariableName
  }

  /** Gets the literal text of this string (its concatenated string content). */
  string getValue() {
    result = this.(Php::String).getChild(_).(Php::StringContent).getValue() or
    result = this.(Php::EncapsedString).getChild(_).(Php::StringContent).getValue()
  }
}

/** An anonymous function or arrow function — a closure (a first-class callable value). */
class Closure extends Expr {
  Closure() { this instanceof Php::AnonymousFunction or this instanceof Php::ArrowFunction }
}

/** An array literal, `[...]` or `array(...)`. */
class ArrayLiteral extends Expr instanceof Php::ArrayCreationExpression {
  /** Gets an element expression of this array literal. */
  Expr getAnElement() {
    result = super.getChild(_).(Php::ArrayElementInitializer).getChild(_)
  }
}

/** An `include`/`require`/`include_once`/`require_once` expression (file inclusion). */
class IncludeExpr extends Expr {
  IncludeExpr() {
    this instanceof Php::IncludeExpression or
    this instanceof Php::IncludeOnceExpression or
    this instanceof Php::RequireExpression or
    this instanceof Php::RequireOnceExpression
  }

  /** Gets the included path expression. */
  Expr getPath() {
    result = this.(Php::IncludeExpression).getChild() or
    result = this.(Php::IncludeOnceExpression).getChild() or
    result = this.(Php::RequireExpression).getChild() or
    result = this.(Php::RequireOnceExpression).getChild()
  }
}

/** A backtick shell-command expression, `` `cmd` `` (executes a shell command). */
class ShellCommandExpr extends Expr instanceof Php::ShellCommandExpression {
  /** Gets a part of the shell command. */
  Expr getAPart() { result = super.getChild(_) }
}

/** A `throw` expression. */
class ThrowExpr extends Expr instanceof Php::ThrowExpression {
  /** Gets the thrown expression. */
  Expr getThrown() { result = super.getChild() }
}

/** A `clone $x` expression. */
class CloneExpr extends Expr instanceof Php::CloneExpression {
  /** Gets the cloned expression. */
  Expr getOperand() { result = super.getChild() }
}

/** A `print` expression (a language construct, not a function call). */
class PrintExpr extends Expr instanceof Php::PrintIntrinsic {
  /** Gets the printed operand. */
  Expr getOperand() { result = super.getChild() }
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

/** A field / property access, `$obj->field`. */
class FieldAccess extends Expr instanceof Php::MemberAccessExpression {
  /** Gets the object whose field is accessed. */
  Expr getObject() { result = super.getObject() }

  /** Gets the accessed field name, e.g. `"field"` in `$obj->field`. */
  string getFieldName() { result = super.getName().(Php::Name).getValue() }
}

/** A cast expression, e.g. `(int) $x`. */
class CastExpr extends Expr instanceof Php::CastExpression {
  /** Gets the target type name, e.g. `int`. */
  string getTypeName() { result = super.getType().getValue() }

  /** Gets the expression being cast. */
  Expr getOperand() { result = super.getValue().(Expr) }
}
