/**
 * Provides classes for PHP type declarations (classes, interfaces, traits, enums)
 * and their inheritance relationships.
 */

private import codeql.php.ast.internal.TreeSitter
private import codeql.php.ast.internal.Naming
private import codeql.php.ast.internal.Namespace as NS
import codeql.php.ast.AstNode
import codeql.php.ast.Callable

/**
 * A type-like declaration: a `class`, `interface`, `trait` or `enum`.
 */
class ClassLike extends AstNode {
  ClassLike() {
    this instanceof Php::ClassDeclaration or
    this instanceof Php::InterfaceDeclaration or
    this instanceof Php::TraitDeclaration or
    this instanceof Php::EnumDeclaration
  }

  /** Gets the declared (unqualified) name of this type, e.g. `Dog`. */
  string getName() {
    result = this.(Php::ClassDeclaration).getName().getValue() or
    result = this.(Php::InterfaceDeclaration).getName().getValue() or
    result = this.(Php::TraitDeclaration).getName().getValue() or
    result = this.(Php::EnumDeclaration).getName().getValue()
  }

  /** Gets a member node declared in this type's body. */
  private Php::AstNode getABodyMember() {
    result = this.(Php::ClassDeclaration).getBody().getChild(_) or
    result = this.(Php::InterfaceDeclaration).getBody().getChild(_) or
    result = this.(Php::TraitDeclaration).getBody().getChild(_) or
    result = this.(Php::EnumDeclaration).getBody().getChild(_)
  }

  /** Gets a method declared directly in this type (not inherited). */
  Method getADeclaredMethod() { result.getDeclaringType() = this }

  /** Gets the namespace this type is declared in (empty string for the global namespace). */
  string getNamespace() { result = NS::enclosingNamespace(this) }

  /**
   * Gets the fully-qualified name of this type, e.g. `App\Domain\Dog`
   * (or just `Dog` if declared in the global namespace).
   */
  string getQualifiedName() {
    exists(string ns | ns = this.getNamespace() |
      if ns = "" then result = this.getName() else result = ns + "\\" + this.getName()
    )
  }

  /** Gets a name-reference node in this type's `extends` clause. */
  private Php::AstNode getASuperTypeRef() {
    exists(Php::BaseClause bc |
      bc = this.(Php::ClassDeclaration).getChild(_) and result = bc.getChild(_)
    )
    or
    exists(Php::BaseClause bc |
      bc = this.(Php::InterfaceDeclaration).getChild() and result = bc.getChild(_)
    )
  }

  /** Gets a name-reference node in this type's `implements` clause. */
  private Php::AstNode getAnImplementedRef() {
    exists(Php::ClassInterfaceClause cic |
      cic = this.(Php::ClassDeclaration).getChild(_) and result = cic.getChild(_)
    )
  }

  /** Gets a name-reference node for a trait `use`d in this type's body. */
  private Php::AstNode getAUsedTraitRef() {
    exists(Php::UseDeclaration ud | ud = this.getABodyMember() and result = ud.getChild(_))
  }

  /** Gets the superclass of this class, or a super-interface of this interface. */
  ClassLike getASuperType() { result = resolveClassReference(this.getASuperTypeRef().(AstNode)) }

  /** Gets an interface directly implemented by this class. */
  ClassLike getAnImplementedInterface() {
    result = resolveClassReference(this.getAnImplementedRef().(AstNode))
  }

  /** Gets a trait directly `use`d by this type. */
  ClassLike getAUsedTrait() {
    result = resolveClassReference(this.getAUsedTraitRef().(AstNode)) and result instanceof Php::TraitDeclaration
  }

  /** Gets a direct super type: superclass or a directly implemented interface. */
  ClassLike getADirectSuperType() {
    result = this.getASuperType() or result = this.getAnImplementedInterface()
  }

  /** Gets a (transitive, reflexive-free) ancestor type of this type. */
  ClassLike getAnAncestor() {
    result = this.getADirectSuperType()
    or
    result = this.getADirectSuperType().getAnAncestor()
  }

  /** Gets a trait used by this type, transitively through ancestors and trait-of-trait use. */
  ClassLike getATransitivelyUsedTrait() {
    result = this.getAUsedTrait()
    or
    result = this.getAnAncestor().getAUsedTrait()
    or
    result = this.getATransitivelyUsedTrait().getAUsedTrait()
  }

  /**
   * Gets a method available on this type: declared here, inherited from an ancestor,
   * or flattened in from a `use`d trait (including traits used by ancestors).
   */
  Method getAMethod() {
    result = this.getADeclaredMethod()
    or
    result = this.getAnAncestor().getADeclaredMethod()
    or
    result = this.getATransitivelyUsedTrait().getADeclaredMethod()
  }
}

/**
 * Resolves a class-reference node (a bare `Name` or a `QualifiedName`) to the type it denotes,
 * matching on both the simple name and the namespace it points into.
 *
 * This disambiguates identical short names living in different namespaces. `use`-import aliases
 * are not yet followed (a known refinement).
 */
ClassLike resolveClassReference(AstNode ref) {
  result.getName() = simpleNameOf(ref) and
  result.getNamespace() = NS::referencedNamespace(ref)
  or
  // Follow a `use Qualified\Name as Alias;` import when `ref` is the bare alias (same file).
  not ref instanceof Php::QualifiedName and
  exists(Php::NamespaceUseClause uc |
    uc.getAlias().toString() = simpleNameOf(ref) and
    uc.getLocation().getFile() = ref.getLocation().getFile() and
    result = resolveClassReference(uc.getChild().(AstNode))
  )
}

/** A `class` declaration. */
class Class extends ClassLike instanceof Php::ClassDeclaration {
  /** Holds if this class is declared `abstract`. */
  predicate isAbstract() { super.getChild(_) instanceof Php::AbstractModifier }

  /** Holds if this class is declared `final`. */
  predicate isFinal() { super.getChild(_) instanceof Php::FinalModifier }
}

/** An `interface` declaration. */
class Interface extends ClassLike instanceof Php::InterfaceDeclaration { }

/** A `trait` declaration. */
class Trait extends ClassLike instanceof Php::TraitDeclaration { }

/** An `enum` declaration (PHP 8.1+). */
class Enum extends ClassLike instanceof Php::EnumDeclaration { }
