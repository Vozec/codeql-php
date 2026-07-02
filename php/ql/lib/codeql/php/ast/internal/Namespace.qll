/**
 * Internal helpers for PHP namespace resolution.
 *
 * PHP declares namespaces in two forms:
 *  - statement form: `namespace App\Domain;` governs every following sibling until the next such
 *    statement;
 *  - block form: `namespace App\Domain { ... }` scopes only its body.
 *
 * These predicates compute the namespace string in effect at any node, so that class references
 * can be resolved to the right declaration even when the same short name exists in several
 * namespaces. Global scope is represented by the empty string.
 */

private import codeql.php.ast.internal.TreeSitter

/** Gets the backslash-joined string of a `namespace_name` node, e.g. `"App\Domain"`. */
string nsNameToString(Php::NamespaceName nn) {
  result = concat(int i | exists(nn.getChild(i)) | nn.getChild(i).getValue(), "\\" order by i)
}

/** Gets the dotted namespace name of `nd`, e.g. `"App\Domain"`. */
string namespaceName(Php::NamespaceDefinition nd) { result = nsNameToString(nd.getName()) }

/** Gets a block-form namespace whose body encloses `n`. */
private Php::NamespaceDefinition bodyNamespaceOf(Php::AstNode n) {
  exists(result.getBody()) and result.getBody() = n.getParent+()
}

/** Gets the top-level statement (direct child of the program) that contains `n`. */
private Php::AstNode topLevelStmtOf(Php::AstNode n) {
  result = n.getParent*() and result.getParent() instanceof Php::Program
}

/** Gets the statement-form namespace that governs the top-level statement `topStmt`. */
private Php::NamespaceDefinition governingNamespace(Php::AstNode topStmt) {
  not exists(result.getBody()) and
  result.getParent() = topStmt.getParent() and
  result.getParentIndex() < topStmt.getParentIndex() and
  not exists(Php::NamespaceDefinition other |
    not exists(other.getBody()) and
    other.getParent() = topStmt.getParent() and
    result.getParentIndex() < other.getParentIndex() and
    other.getParentIndex() < topStmt.getParentIndex()
  )
}

/**
 * Gets the namespace in effect at node `n` (the empty string for the global namespace).
 * This is total: every node has exactly one enclosing namespace string.
 */
string enclosingNamespace(Php::AstNode n) {
  result = namespaceName(bodyNamespaceOf(n))
  or
  not exists(bodyNamespaceOf(n)) and result = namespaceName(governingNamespace(topLevelStmtOf(n)))
  or
  not exists(bodyNamespaceOf(n)) and
  not exists(governingNamespace(topLevelStmtOf(n))) and
  result = ""
}

/**
 * Gets the namespace that a class-reference node `ref` points into.
 *
 * For a bare name this is the namespace in effect at the reference; for a qualified name
 * (`App\Domain\Dog`) it is the qualifier (`App\Domain`).
 */
string referencedNamespace(Php::AstNode ref) {
  ref instanceof Php::Name and result = enclosingNamespace(ref)
  or
  exists(Php::QualifiedName qn | qn = ref |
    result = nsNameToString(qn.getPrefix(_))
    or
    not qn.getPrefix(_) instanceof Php::NamespaceName and result = ""
  )
}
