/** Provides classes for PHP call expressions. */

private import codeql.php.ast.internal.TreeSitter
private import codeql.php.ast.internal.Naming
import codeql.php.ast.AstNode
import codeql.php.ast.Expr

/**
 * A call: a function call, method call, static method call, or object creation (`new`).
 */
class Call extends Expr {
  Call() {
    this instanceof Php::FunctionCallExpression or
    this instanceof Php::MemberCallExpression or
    this instanceof Php::NullsafeMemberCallExpression or
    this instanceof Php::ScopedCallExpression or
    this instanceof Php::ObjectCreationExpression
  }

  /** Gets the `arguments` node backing this call, if any. */
  private Php::Arguments getArgsNode() {
    result = this.(Php::FunctionCallExpression).getArguments() or
    result = this.(Php::MemberCallExpression).getArguments() or
    result = this.(Php::NullsafeMemberCallExpression).getArguments() or
    result = this.(Php::ScopedCallExpression).getArguments() or
    result = this.(Php::ObjectCreationExpression).getChild(_)
  }

  /** Gets the `i`th argument expression of this call. */
  Expr getArgument(int i) {
    exists(Php::Argument a | a = this.getArgsNode().getChild(i) | result = a.getChild().(Expr))
  }

  /** Gets an argument expression of this call. */
  Expr getAnArgument() { result = this.getArgument(_) }
}

/** A call to a named (global/namespaced) function, e.g. `system($cmd)`. */
class FunctionCall extends Call instanceof Php::FunctionCallExpression {
  /** Gets the called function's (last-segment) name, e.g. `system`. */
  string getName() { result = simpleNameOf(super.getFunction()) }

  /** Holds if this is a dynamic call whose target is not a static name (e.g. `$fn()`). */
  predicate isDynamic() { not exists(this.getName()) }
}

/** An instance method call, `$obj->method(...)` or `$obj?->method(...)`. */
class MethodCall extends Call {
  MethodCall() {
    this instanceof Php::MemberCallExpression or
    this instanceof Php::NullsafeMemberCallExpression
  }

  /** Gets the receiver object expression. */
  Expr getReceiver() {
    result = this.(Php::MemberCallExpression).getObject() or
    result = this.(Php::NullsafeMemberCallExpression).getObject()
  }

  /** Gets the (last-segment) method name, if it is statically known. */
  string getMethodName() {
    result = simpleNameOf(this.(Php::MemberCallExpression).getName()) or
    result = simpleNameOf(this.(Php::NullsafeMemberCallExpression).getName())
  }

  /** Holds if this uses the nullsafe operator `?->`. */
  predicate isNullsafe() { this instanceof Php::NullsafeMemberCallExpression }
}

/** A static method call, `Foo::bar(...)`. */
class StaticMethodCall extends Call instanceof Php::ScopedCallExpression {
  /** Gets the (last-segment) name of the target class/scope, e.g. `Foo`, `self`, `static`. */
  string getTargetName() { result = simpleNameOf(super.getScope()) }

  /** Gets the (last-segment) method name. */
  string getMethodName() { result = simpleNameOf(super.getName()) }
}

/** An object creation, `new Foo(...)` or `new $cls(...)`. */
class NewExpr extends Call instanceof Php::ObjectCreationExpression {
  /** Gets the (last-segment) name of the instantiated class, if statically known. */
  string getClassName() { result = simpleNameOf(super.getChild(_)) }
}
