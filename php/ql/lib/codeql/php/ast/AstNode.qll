/** Provides the base class for all PHP AST nodes in the ergonomic library. */

private import codeql.php.ast.internal.TreeSitter
import codeql.Locations

/**
 * A node in the PHP abstract syntax tree.
 *
 * This is the ergonomic wrapper over the raw tree-sitter node (`Php::AstNode`),
 * and the common supertype of every hand-written AST class.
 */
class AstNode instanceof Php::AstNode {
  /** Gets a textual representation of this node. */
  string toString() { result = this.getPrimaryQlClass() }

  /** Gets the source location of this node. */
  Location getLocation() { result = super.getLocation() }

  /** Gets the parent of this node, if any. */
  AstNode getParent() { result = super.getParent() }

  /** Gets a child (field or ordered child) of this node. */
  AstNode getAChild() { result = super.getAFieldOrChild() }

  /** Gets the name of the primary generated QL class for this node. */
  string getPrimaryQlClass() { result = super.getAPrimaryQlClass() }

  /** Gets the file this node belongs to. */
  File getFile() { result = this.getLocation().getFile() }
}
