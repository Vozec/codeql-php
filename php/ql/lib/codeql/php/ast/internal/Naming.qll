/** Internal helpers for resolving name references (class names, function names, …). */

private import codeql.php.ast.internal.TreeSitter

/**
 * Gets the (unqualified, last-segment) textual name denoted by the name node `n`,
 * which may be a bare `Name` or a namespaced `QualifiedName`.
 *
 * For `\App\Domain\Dog` this yields `"Dog"`. Full namespace-aware resolution is a
 * later refinement; matching on the last segment already resolves the common case.
 */
string simpleNameOf(Php::AstNode n) {
  result = n.(Php::Name).getValue()
  or
  result = n.(Php::QualifiedName).getChild().getValue()
}
