/** Provides classes for PHP callables: functions, methods, closures and arrow functions. */

private import codeql.php.ast.internal.TreeSitter
import codeql.php.ast.AstNode

/**
 * A callable: a global function, a method, a closure or an arrow function.
 */
class Callable extends AstNode {
  Callable() {
    this instanceof Php::FunctionDefinition or
    this instanceof Php::MethodDeclaration or
    this instanceof Php::AnonymousFunction or
    this instanceof Php::ArrowFunction
  }

  /** Gets the body of this callable, if it has one. */
  AstNode getBody() {
    result = this.(Php::FunctionDefinition).getBody() or
    result = this.(Php::MethodDeclaration).getBody() or
    result = this.(Php::AnonymousFunction).getBody() or
    result = this.(Php::ArrowFunction).getBody()
  }

  /** Gets the `i`th formal parameter of this callable. */
  Parameter getParameter(int i) {
    result =
      [
        this.(Php::FunctionDefinition).getParameters(),
        this.(Php::MethodDeclaration).getParameters(),
        this.(Php::AnonymousFunction).getParameters(),
        this.(Php::ArrowFunction).getParameters()
      ].getChild(i)
  }

  /** Gets a formal parameter of this callable. */
  Parameter getAParameter() { result = this.getParameter(_) }
}

/** A named, top-level (global or namespaced) function definition. */
class Function extends Callable instanceof Php::FunctionDefinition {
  /** Gets the declared name of this function, e.g. `greet`. */
  string getName() { result = super.getName().getValue() }
}

/** A method declared inside a class, interface, trait or enum. */
class Method extends Callable instanceof Php::MethodDeclaration {
  /** Gets the declared name of this method, e.g. `speak`. */
  string getName() { result = super.getName().getValue() }

  /**
   * Gets the type (class/interface/trait/enum) that directly declares this method.
   *
   * A method node sits inside a declaration list, which is the body of the type,
   * so the declaring type is exactly two parents up.
   */
  AstNode getDeclaringType() {
    result = this.(Php::MethodDeclaration).getParent().getParent()
  }

  /** Holds if this method is declared `static`. */
  predicate isStatic() { super.getChild(_) instanceof Php::StaticModifier }

  /** Holds if this method is declared `abstract`. */
  predicate isAbstract() { super.getChild(_) instanceof Php::AbstractModifier }
}

/** A formal parameter of a callable. */
class Parameter extends AstNode {
  Parameter() {
    this instanceof Php::SimpleParameter or
    this instanceof Php::VariadicParameter or
    this instanceof Php::PropertyPromotionParameter
  }

  /** Gets the parameter name (without the leading `$`). */
  string getName() {
    result = this.(Php::SimpleParameter).getName().getChild().getValue() or
    result = this.(Php::VariadicParameter).getName().getChild().getValue() or
    result =
      this.(Php::PropertyPromotionParameter).getName().(Php::VariableName).getChild().getValue()
  }
}
