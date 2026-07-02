/**
* CodeQL library for Php
          * Automatically generated from the tree-sitter grammar; do not edit
*/

import codeql.Locations as L

/** Holds if the database is an overlay. */overlay[local] private predicate isOverlay() { databaseMetadata("isOverlay", "true") }

/** Holds if `loc` is in the `file` and is part of the overlay base database. */overlay[local] private predicate discardableLocation(@file file, @location_default loc) { (not (isOverlay())) and (locations_default(loc, file, _, _, _, _)) }

/** Holds if `loc` should be discarded, because it is part of the overlay base and is in a file that was also extracted as part of the overlay database. */overlay[discard_entity] private predicate discardLocation(@location_default loc) { exists(@file file, string path | files(file, path) | (discardableLocation(file, loc)) and (overlayChangedFiles(path))) }

overlay[local] module Php { 
  /** The base class for all AST nodes */private class AstNodeImpl extends @php_ast_node { 
  /** Gets a string representation of this element. */string toString() { result = this.getAPrimaryQlClass() }
  /** Gets the location of this element. */final L::Location getLocation() { php_ast_node_location(this, result) }
  /** Gets the parent of this element. */final AstNode getParent() { php_ast_node_parent(this, result, _) }
  /** Gets the index of this node among the children of its parent. */final int getParentIndex() { php_ast_node_parent(this, _, result) }
  /** Gets a field or child node of this node. */AstNode getAFieldOrChild() { none() }
  /** Gets the name of the primary QL class for this element. */string getAPrimaryQlClass() { result = "???" }
  /** Gets a comma-separated list of the names of the primary CodeQL classes to which this element belongs. */string getPrimaryQlClasses() { result = concat(this.getAPrimaryQlClass(), ",") }
}
  final class AstNode = AstNodeImpl;
  /** A token. */private class TokenImpl extends @php_token, AstNodeImpl { 
  /** Gets the value of this token. */final string getValue() { php_tokeninfo(this, _, result) }
  /** Gets a string representation of this element. */final override string toString() { result = this.getValue() }
  /** Gets the name of the primary QL class for this element. */override string getAPrimaryQlClass() { result = "Token" }
}
  final class Token = TokenImpl;
  /** A reserved word. */final class ReservedWord extends @php_reserved_word, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ReservedWord" }
}
  /** Gets the file containing the given `node`. */private @file getNodeFile(@php_ast_node node) { exists(@location_default loc | php_ast_node_location(node, loc) | locations_default(loc, result, _, _, _, _)) }
  /** Holds if `node` is in the `file` and is part of the overlay base database. */private predicate discardableAstNode(@file file, @php_ast_node node) { (not (isOverlay())) and (file = getNodeFile(node)) }
  /** Holds if `node` should be discarded, because it is part of the overlay base and is in a file that was also extracted as part of the overlay database. */overlay[discard_entity] private predicate discardAstNode(@php_ast_node node) { exists(@file file, string path | files(file, path) | (discardableAstNode(file, node)) and (overlayChangedFiles(path))) }
  /** A class representing `abstract_modifier` tokens. */final class AbstractModifier extends @php_token_abstract_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AbstractModifier" }
}
  /** A class representing `anonymous_class` nodes. */final class AnonymousClass extends @php_anonymous_class, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AnonymousClass" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_anonymous_class_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final DeclarationList getBody() { php_anonymous_class_def(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_anonymous_class_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_anonymous_class_attributes(this, result)) or (php_anonymous_class_def(this, result)) or (php_anonymous_class_child(this, _, result)) }
}
  /** A class representing `anonymous_function` nodes. */final class AnonymousFunction extends @php_anonymous_function, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AnonymousFunction" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_anonymous_function_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_anonymous_function_def(this, result, _) }
  /** Gets the node corresponding to the field `parameters`. */final FormalParameters getParameters() { php_anonymous_function_def(this, _, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_anonymous_function_reference_modifier(this, result) }
  /** Gets the node corresponding to the field `return_type`. */final AstNode getReturnType() { php_anonymous_function_return_type(this, result) }
  /** Gets the node corresponding to the field `static_modifier`. */final StaticModifier getStaticModifier() { php_anonymous_function_static_modifier(this, result) }
  /** Gets the child of this node. */final AnonymousFunctionUseClause getChild() { php_anonymous_function_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_anonymous_function_attributes(this, result)) or (php_anonymous_function_def(this, result, _)) or (php_anonymous_function_def(this, _, result)) or (php_anonymous_function_reference_modifier(this, result)) or (php_anonymous_function_return_type(this, result)) or (php_anonymous_function_static_modifier(this, result)) or (php_anonymous_function_child(this, result)) }
}
  /** A class representing `anonymous_function_use_clause` nodes. */final class AnonymousFunctionUseClause extends @php_anonymous_function_use_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AnonymousFunctionUseClause" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_anonymous_function_use_clause_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_anonymous_function_use_clause_child(this, _, result)) }
}
  /** A class representing `argument` nodes. */final class Argument extends @php_argument, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Argument" }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_argument_name(this, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_argument_reference_modifier(this, result) }
  /** Gets the child of this node. */final AstNode getChild() { php_argument_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_argument_name(this, result)) or (php_argument_reference_modifier(this, result)) or (php_argument_def(this, result)) }
}
  /** A class representing `arguments` nodes. */final class Arguments extends @php_arguments, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Arguments" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_arguments_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_arguments_child(this, _, result)) }
}
  /** A class representing `array_creation_expression` nodes. */final class ArrayCreationExpression extends @php_array_creation_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ArrayCreationExpression" }
  /** Gets the `i`th child of this node. */final ArrayElementInitializer getChild(int i) { php_array_creation_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_array_creation_expression_child(this, _, result)) }
}
  /** A class representing `array_element_initializer` nodes. */final class ArrayElementInitializer extends @php_array_element_initializer, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ArrayElementInitializer" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_array_element_initializer_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_array_element_initializer_child(this, _, result)) }
}
  /** A class representing `arrow_function` nodes. */final class ArrowFunction extends @php_arrow_function, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ArrowFunction" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_arrow_function_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final Expression getBody() { php_arrow_function_def(this, result, _) }
  /** Gets the node corresponding to the field `parameters`. */final FormalParameters getParameters() { php_arrow_function_def(this, _, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_arrow_function_reference_modifier(this, result) }
  /** Gets the node corresponding to the field `return_type`. */final AstNode getReturnType() { php_arrow_function_return_type(this, result) }
  /** Gets the node corresponding to the field `static_modifier`. */final StaticModifier getStaticModifier() { php_arrow_function_static_modifier(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_arrow_function_attributes(this, result)) or (php_arrow_function_def(this, result, _)) or (php_arrow_function_def(this, _, result)) or (php_arrow_function_reference_modifier(this, result)) or (php_arrow_function_return_type(this, result)) or (php_arrow_function_static_modifier(this, result)) }
}
  /** A class representing `assignment_expression` nodes. */final class AssignmentExpression extends @php_assignment_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AssignmentExpression" }
  /** Gets the node corresponding to the field `left`. */final AstNode getLeft() { php_assignment_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `right`. */final Expression getRight() { php_assignment_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_assignment_expression_def(this, result, _)) or (php_assignment_expression_def(this, _, result)) }
}
  /** A class representing `attribute` nodes. */final class Attribute extends @php_attribute, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Attribute" }
  /** Gets the node corresponding to the field `parameters`. */final Arguments getParameters() { php_attribute_parameters(this, result) }
  /** Gets the child of this node. */final AstNode getChild() { php_attribute_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_attribute_parameters(this, result)) or (php_attribute_def(this, result)) }
}
  /** A class representing `attribute_group` nodes. */final class AttributeGroup extends @php_attribute_group, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AttributeGroup" }
  /** Gets the `i`th child of this node. */final Attribute getChild(int i) { php_attribute_group_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_attribute_group_child(this, _, result)) }
}
  /** A class representing `attribute_list` nodes. */final class AttributeList extends @php_attribute_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AttributeList" }
  /** Gets the `i`th child of this node. */final AttributeGroup getChild(int i) { php_attribute_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_attribute_list_child(this, _, result)) }
}
  /** A class representing `augmented_assignment_expression` nodes. */final class AugmentedAssignmentExpression extends @php_augmented_assignment_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "AugmentedAssignmentExpression" }
  /** Gets the node corresponding to the field `left`. */final AstNode getLeft() { php_augmented_assignment_expression_def(this, result, _, _) }
  /** Gets the node corresponding to the field `operator`. */final string getOperator() { exists(int value | php_augmented_assignment_expression_def(this, _, value, _) | ((result = "%=") and (value = 0)) or ((result = "&=") and (value = 1)) or ((result = "**=") and (value = 2)) or ((result = "*=") and (value = 3)) or ((result = "+=") and (value = 4)) or ((result = "-=") and (value = 5)) or ((result = ".=") and (value = 6)) or ((result = "/=") and (value = 7)) or ((result = "<<=") and (value = 8)) or ((result = ">>=") and (value = 9)) or ((result = "??=") and (value = 10)) or ((result = "^=") and (value = 11)) or ((result = "|=") and (value = 12))) }
  /** Gets the node corresponding to the field `right`. */final Expression getRight() { php_augmented_assignment_expression_def(this, _, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_augmented_assignment_expression_def(this, result, _, _)) or (php_augmented_assignment_expression_def(this, _, _, result)) }
}
  /** A class representing `base_clause` nodes. */final class BaseClause extends @php_base_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "BaseClause" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_base_clause_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_base_clause_child(this, _, result)) }
}
  /** A class representing `binary_expression` nodes. */final class BinaryExpression extends @php_binary_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "BinaryExpression" }
  /** Gets the node corresponding to the field `left`. */final Expression getLeft() { php_binary_expression_def(this, result, _, _) }
  /** Gets the node corresponding to the field `operator`. */final string getOperator() { exists(int value | php_binary_expression_def(this, _, value, _) | ((result = "!=") and (value = 0)) or ((result = "!==") and (value = 1)) or ((result = "%") and (value = 2)) or ((result = "&") and (value = 3)) or ((result = "&&") and (value = 4)) or ((result = "*") and (value = 5)) or ((result = "**") and (value = 6)) or ((result = "+") and (value = 7)) or ((result = "-") and (value = 8)) or ((result = ".") and (value = 9)) or ((result = "/") and (value = 10)) or ((result = "<") and (value = 11)) or ((result = "<<") and (value = 12)) or ((result = "<=") and (value = 13)) or ((result = "<=>") and (value = 14)) or ((result = "<>") and (value = 15)) or ((result = "==") and (value = 16)) or ((result = "===") and (value = 17)) or ((result = ">") and (value = 18)) or ((result = ">=") and (value = 19)) or ((result = ">>") and (value = 20)) or ((result = "??") and (value = 21)) or ((result = "^") and (value = 22)) or ((result = "and") and (value = 23)) or ((result = "instanceof") and (value = 24)) or ((result = "or") and (value = 25)) or ((result = "xor") and (value = 26)) or ((result = "|") and (value = 27)) or ((result = "|>") and (value = 28)) or ((result = "||") and (value = 29))) }
  /** Gets the node corresponding to the field `right`. */final AstNode getRight() { php_binary_expression_def(this, _, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_binary_expression_def(this, result, _, _)) or (php_binary_expression_def(this, _, _, result)) }
}
  /** A class representing `boolean` tokens. */final class Boolean extends @php_token_boolean, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Boolean" }
}
  /** A class representing `bottom_type` tokens. */final class BottomType extends @php_token_bottom_type, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "BottomType" }
}
  /** A class representing `break_statement` nodes. */final class BreakStatement extends @php_break_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "BreakStatement" }
  /** Gets the child of this node. */final Expression getChild() { php_break_statement_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_break_statement_child(this, result)) }
}
  /** A class representing `by_ref` nodes. */final class ByRef extends @php_by_ref, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ByRef" }
  /** Gets the child of this node. */final AstNode getChild() { php_by_ref_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_by_ref_def(this, result)) }
}
  /** A class representing `case_statement` nodes. */final class CaseStatement extends @php_case_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CaseStatement" }
  /** Gets the node corresponding to the field `value`. */final Expression getValue() { php_case_statement_def(this, result) }
  /** Gets the `i`th child of this node. */final Statement getChild(int i) { php_case_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_case_statement_def(this, result)) or (php_case_statement_child(this, _, result)) }
}
  /** A class representing `cast_expression` nodes. */final class CastExpression extends @php_cast_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CastExpression" }
  /** Gets the node corresponding to the field `type`. */final CastType getType() { php_cast_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `value`. */final AstNode getValue() { php_cast_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_cast_expression_def(this, result, _)) or (php_cast_expression_def(this, _, result)) }
}
  /** A class representing `cast_type` tokens. */final class CastType extends @php_token_cast_type, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CastType" }
}
  /** A class representing `catch_clause` nodes. */final class CatchClause extends @php_catch_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CatchClause" }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_catch_clause_def(this, result, _) }
  /** Gets the node corresponding to the field `name`. */final VariableName getName() { php_catch_clause_name(this, result) }
  /** Gets the node corresponding to the field `type`. */final TypeList getType() { php_catch_clause_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_catch_clause_def(this, result, _)) or (php_catch_clause_name(this, result)) or (php_catch_clause_def(this, _, result)) }
}
  /** A class representing `class_constant_access_expression` nodes. */final class ClassConstantAccessExpression extends @php_class_constant_access_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ClassConstantAccessExpression" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_class_constant_access_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_class_constant_access_expression_child(this, _, result)) }
}
  /** A class representing `class_declaration` nodes. */final class ClassDeclaration extends @php_class_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ClassDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_class_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final DeclarationList getBody() { php_class_declaration_def(this, result, _) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_class_declaration_def(this, _, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_class_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_class_declaration_attributes(this, result)) or (php_class_declaration_def(this, result, _)) or (php_class_declaration_def(this, _, result)) or (php_class_declaration_child(this, _, result)) }
}
  /** A class representing `class_interface_clause` nodes. */final class ClassInterfaceClause extends @php_class_interface_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ClassInterfaceClause" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_class_interface_clause_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_class_interface_clause_child(this, _, result)) }
}
  /** A class representing `clone_expression` nodes. */final class CloneExpression extends @php_clone_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CloneExpression" }
  /** Gets the child of this node. */final PrimaryExpression getChild() { php_clone_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_clone_expression_def(this, result)) }
}
  /** A class representing `colon_block` nodes. */final class ColonBlock extends @php_colon_block, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ColonBlock" }
  /** Gets the `i`th child of this node. */final Statement getChild(int i) { php_colon_block_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_colon_block_child(this, _, result)) }
}
  /** A class representing `comment` tokens. */final class Comment extends @php_token_comment, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Comment" }
}
  /** A class representing `compound_statement` nodes. */final class CompoundStatement extends @php_compound_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "CompoundStatement" }
  /** Gets the `i`th child of this node. */final Statement getChild(int i) { php_compound_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_compound_statement_child(this, _, result)) }
}
  /** A class representing `conditional_expression` nodes. */final class ConditionalExpression extends @php_conditional_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ConditionalExpression" }
  /** Gets the node corresponding to the field `alternative`. */final Expression getAlternative() { php_conditional_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `body`. */final Expression getBody() { php_conditional_expression_body(this, result) }
  /** Gets the node corresponding to the field `condition`. */final Expression getCondition() { php_conditional_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_conditional_expression_def(this, result, _)) or (php_conditional_expression_body(this, result)) or (php_conditional_expression_def(this, _, result)) }
}
  /** A class representing `const_declaration` nodes. */final class ConstDeclaration extends @php_const_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ConstDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_const_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `type`. */final Type getType() { php_const_declaration_type(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_const_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_const_declaration_attributes(this, result)) or (php_const_declaration_type(this, result)) or (php_const_declaration_child(this, _, result)) }
}
  /** A class representing `const_element` nodes. */final class ConstElement extends @php_const_element, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ConstElement" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_const_element_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_const_element_child(this, _, result)) }
}
  /** A class representing `continue_statement` nodes. */final class ContinueStatement extends @php_continue_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ContinueStatement" }
  /** Gets the child of this node. */final Expression getChild() { php_continue_statement_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_continue_statement_child(this, result)) }
}
  /** A class representing `declaration_list` nodes. */final class DeclarationList extends @php_declaration_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DeclarationList" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_declaration_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_declaration_list_child(this, _, result)) }
}
  /** A class representing `declare_directive` nodes. */final class DeclareDirective extends @php_declare_directive, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DeclareDirective" }
  /** Gets the child of this node. */final Literal getChild() { php_declare_directive_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_declare_directive_def(this, result)) }
}
  /** A class representing `declare_statement` nodes. */final class DeclareStatement extends @php_declare_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DeclareStatement" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_declare_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_declare_statement_child(this, _, result)) }
}
  /** A class representing `default_statement` nodes. */final class DefaultStatement extends @php_default_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DefaultStatement" }
  /** Gets the `i`th child of this node. */final Statement getChild(int i) { php_default_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_default_statement_child(this, _, result)) }
}
  /** A class representing `disjunctive_normal_form_type` nodes. */final class DisjunctiveNormalFormType extends @php_disjunctive_normal_form_type, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DisjunctiveNormalFormType" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_disjunctive_normal_form_type_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_disjunctive_normal_form_type_child(this, _, result)) }
}
  /** A class representing `do_statement` nodes. */final class DoStatement extends @php_do_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DoStatement" }
  /** Gets the node corresponding to the field `body`. */final Statement getBody() { php_do_statement_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_do_statement_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_do_statement_def(this, result, _)) or (php_do_statement_def(this, _, result)) }
}
  /** A class representing `dynamic_variable_name` nodes. */final class DynamicVariableName extends @php_dynamic_variable_name, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "DynamicVariableName" }
  /** Gets the child of this node. */final AstNode getChild() { php_dynamic_variable_name_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_dynamic_variable_name_def(this, result)) }
}
  /** A class representing `echo_statement` nodes. */final class EchoStatement extends @php_echo_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EchoStatement" }
  /** Gets the child of this node. */final AstNode getChild() { php_echo_statement_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_echo_statement_def(this, result)) }
}
  /** A class representing `else_clause` nodes. */final class ElseClause extends @php_else_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ElseClause" }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_else_clause_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_else_clause_def(this, result)) }
}
  /** A class representing `else_if_clause` nodes. */final class ElseIfClause extends @php_else_if_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ElseIfClause" }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_else_if_clause_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_else_if_clause_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_else_if_clause_def(this, result, _)) or (php_else_if_clause_def(this, _, result)) }
}
  /** A class representing `empty_statement` tokens. */final class EmptyStatement extends @php_token_empty_statement, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EmptyStatement" }
}
  /** A class representing `encapsed_string` nodes. */final class EncapsedString extends @php_encapsed_string, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EncapsedString" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_encapsed_string_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_encapsed_string_child(this, _, result)) }
}
  /** A class representing `enum_case` nodes. */final class EnumCase extends @php_enum_case, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EnumCase" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_enum_case_attributes(this, result) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_enum_case_def(this, result) }
  /** Gets the node corresponding to the field `value`. */final Expression getValue() { php_enum_case_value(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_enum_case_attributes(this, result)) or (php_enum_case_def(this, result)) or (php_enum_case_value(this, result)) }
}
  /** A class representing `enum_declaration` nodes. */final class EnumDeclaration extends @php_enum_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EnumDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_enum_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final EnumDeclarationList getBody() { php_enum_declaration_def(this, result, _) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_enum_declaration_def(this, _, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_enum_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_enum_declaration_attributes(this, result)) or (php_enum_declaration_def(this, result, _)) or (php_enum_declaration_def(this, _, result)) or (php_enum_declaration_child(this, _, result)) }
}
  /** A class representing `enum_declaration_list` nodes. */final class EnumDeclarationList extends @php_enum_declaration_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EnumDeclarationList" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_enum_declaration_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_enum_declaration_list_child(this, _, result)) }
}
  /** A class representing `error_suppression_expression` nodes. */final class ErrorSuppressionExpression extends @php_error_suppression_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ErrorSuppressionExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_error_suppression_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_error_suppression_expression_def(this, result)) }
}
  /** A class representing `escape_sequence` tokens. */final class EscapeSequence extends @php_token_escape_sequence, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "EscapeSequence" }
}
  /** A class representing `exit_statement` nodes. */final class ExitStatement extends @php_exit_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ExitStatement" }
  /** Gets the child of this node. */final Expression getChild() { php_exit_statement_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_exit_statement_child(this, result)) }
}
  final class Expression extends @php_expression, AstNodeImpl { 
}
  /** A class representing `expression_statement` nodes. */final class ExpressionStatement extends @php_expression_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ExpressionStatement" }
  /** Gets the child of this node. */final Expression getChild() { php_expression_statement_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_expression_statement_def(this, result)) }
}
  /** A class representing `final_modifier` tokens. */final class FinalModifier extends @php_token_final_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FinalModifier" }
}
  /** A class representing `finally_clause` nodes. */final class FinallyClause extends @php_finally_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FinallyClause" }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_finally_clause_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_finally_clause_def(this, result)) }
}
  /** A class representing `float` tokens. */final class Float extends @php_token_float, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Float" }
}
  /** A class representing `for_statement` nodes. */final class ForStatement extends @php_for_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ForStatement" }
  /** Gets the node corresponding to the field `body`. */final Statement getBody(int i) { php_for_statement_body(this, i, result) }
  /** Gets the node corresponding to the field `condition`. */final AstNode getCondition() { php_for_statement_condition(this, result) }
  /** Gets the node corresponding to the field `initialize`. */final AstNode getInitialize() { php_for_statement_initialize(this, result) }
  /** Gets the node corresponding to the field `update`. */final AstNode getUpdate() { php_for_statement_update(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_for_statement_body(this, _, result)) or (php_for_statement_condition(this, result)) or (php_for_statement_initialize(this, result)) or (php_for_statement_update(this, result)) }
}
  /** A class representing `foreach_statement` nodes. */final class ForeachStatement extends @php_foreach_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ForeachStatement" }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_foreach_statement_body(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_foreach_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_foreach_statement_body(this, result)) or (php_foreach_statement_child(this, _, result)) }
}
  /** A class representing `formal_parameters` nodes. */final class FormalParameters extends @php_formal_parameters, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FormalParameters" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_formal_parameters_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_formal_parameters_child(this, _, result)) }
}
  /** A class representing `function_call_expression` nodes. */final class FunctionCallExpression extends @php_function_call_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FunctionCallExpression" }
  /** Gets the node corresponding to the field `arguments`. */final Arguments getArguments() { php_function_call_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `function`. */final AstNode getFunction() { php_function_call_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_function_call_expression_def(this, result, _)) or (php_function_call_expression_def(this, _, result)) }
}
  /** A class representing `function_definition` nodes. */final class FunctionDefinition extends @php_function_definition, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FunctionDefinition" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_function_definition_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_function_definition_def(this, result, _, _) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_function_definition_def(this, _, result, _) }
  /** Gets the node corresponding to the field `parameters`. */final FormalParameters getParameters() { php_function_definition_def(this, _, _, result) }
  /** Gets the node corresponding to the field `return_type`. */final AstNode getReturnType() { php_function_definition_return_type(this, result) }
  /** Gets the child of this node. */final ReferenceModifier getChild() { php_function_definition_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_function_definition_attributes(this, result)) or (php_function_definition_def(this, result, _, _)) or (php_function_definition_def(this, _, result, _)) or (php_function_definition_def(this, _, _, result)) or (php_function_definition_return_type(this, result)) or (php_function_definition_child(this, result)) }
}
  /** A class representing `function_static_declaration` nodes. */final class FunctionStaticDeclaration extends @php_function_static_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "FunctionStaticDeclaration" }
  /** Gets the `i`th child of this node. */final StaticVariableDeclaration getChild(int i) { php_function_static_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_function_static_declaration_child(this, _, result)) }
}
  /** A class representing `global_declaration` nodes. */final class GlobalDeclaration extends @php_global_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "GlobalDeclaration" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_global_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_global_declaration_child(this, _, result)) }
}
  /** A class representing `goto_statement` nodes. */final class GotoStatement extends @php_goto_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "GotoStatement" }
  /** Gets the child of this node. */final Name getChild() { php_goto_statement_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_goto_statement_def(this, result)) }
}
  /** A class representing `heredoc` nodes. */final class Heredoc extends @php_heredoc, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Heredoc" }
  /** Gets the node corresponding to the field `end_tag`. */final HeredocEnd getEndTag() { php_heredoc_def(this, result, _) }
  /** Gets the node corresponding to the field `identifier`. */final HeredocStart getIdentifier() { php_heredoc_def(this, _, result) }
  /** Gets the node corresponding to the field `value`. */final HeredocBody getValue() { php_heredoc_value(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_heredoc_def(this, result, _)) or (php_heredoc_def(this, _, result)) or (php_heredoc_value(this, result)) }
}
  /** A class representing `heredoc_body` nodes. */final class HeredocBody extends @php_heredoc_body, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "HeredocBody" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_heredoc_body_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_heredoc_body_child(this, _, result)) }
}
  /** A class representing `heredoc_end` tokens. */final class HeredocEnd extends @php_token_heredoc_end, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "HeredocEnd" }
}
  /** A class representing `heredoc_start` tokens. */final class HeredocStart extends @php_token_heredoc_start, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "HeredocStart" }
}
  /** A class representing `if_statement` nodes. */final class IfStatement extends @php_if_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "IfStatement" }
  /** Gets the node corresponding to the field `alternative`. */final AstNode getAlternative(int i) { php_if_statement_alternative(this, i, result) }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_if_statement_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_if_statement_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_if_statement_alternative(this, _, result)) or (php_if_statement_def(this, result, _)) or (php_if_statement_def(this, _, result)) }
}
  /** A class representing `include_expression` nodes. */final class IncludeExpression extends @php_include_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "IncludeExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_include_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_include_expression_def(this, result)) }
}
  /** A class representing `include_once_expression` nodes. */final class IncludeOnceExpression extends @php_include_once_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "IncludeOnceExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_include_once_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_include_once_expression_def(this, result)) }
}
  /** A class representing `integer` tokens. */final class Integer extends @php_token_integer, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Integer" }
}
  /** A class representing `interface_declaration` nodes. */final class InterfaceDeclaration extends @php_interface_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "InterfaceDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_interface_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final DeclarationList getBody() { php_interface_declaration_def(this, result, _) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_interface_declaration_def(this, _, result) }
  /** Gets the child of this node. */final BaseClause getChild() { php_interface_declaration_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_interface_declaration_attributes(this, result)) or (php_interface_declaration_def(this, result, _)) or (php_interface_declaration_def(this, _, result)) or (php_interface_declaration_child(this, result)) }
}
  /** A class representing `intersection_type` nodes. */final class IntersectionType extends @php_intersection_type, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "IntersectionType" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_intersection_type_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_intersection_type_child(this, _, result)) }
}
  /** A class representing `list_literal` nodes. */final class ListLiteral extends @php_list_literal, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ListLiteral" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_list_literal_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_list_literal_child(this, _, result)) }
}
  final class Literal extends @php_literal, AstNodeImpl { 
}
  /** A class representing `match_block` nodes. */final class MatchBlock extends @php_match_block, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MatchBlock" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_match_block_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_match_block_child(this, _, result)) }
}
  /** A class representing `match_condition_list` nodes. */final class MatchConditionList extends @php_match_condition_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MatchConditionList" }
  /** Gets the `i`th child of this node. */final Expression getChild(int i) { php_match_condition_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_match_condition_list_child(this, _, result)) }
}
  /** A class representing `match_conditional_expression` nodes. */final class MatchConditionalExpression extends @php_match_conditional_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MatchConditionalExpression" }
  /** Gets the node corresponding to the field `conditional_expressions`. */final MatchConditionList getConditionalExpressions() { php_match_conditional_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `return_expression`. */final Expression getReturnExpression() { php_match_conditional_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_match_conditional_expression_def(this, result, _)) or (php_match_conditional_expression_def(this, _, result)) }
}
  /** A class representing `match_default_expression` nodes. */final class MatchDefaultExpression extends @php_match_default_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MatchDefaultExpression" }
  /** Gets the node corresponding to the field `return_expression`. */final Expression getReturnExpression() { php_match_default_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_match_default_expression_def(this, result)) }
}
  /** A class representing `match_expression` nodes. */final class MatchExpression extends @php_match_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MatchExpression" }
  /** Gets the node corresponding to the field `body`. */final MatchBlock getBody() { php_match_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_match_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_match_expression_def(this, result, _)) or (php_match_expression_def(this, _, result)) }
}
  /** A class representing `member_access_expression` nodes. */final class MemberAccessExpression extends @php_member_access_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MemberAccessExpression" }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_member_access_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `object`. */final AstNode getObject() { php_member_access_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_member_access_expression_def(this, result, _)) or (php_member_access_expression_def(this, _, result)) }
}
  /** A class representing `member_call_expression` nodes. */final class MemberCallExpression extends @php_member_call_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MemberCallExpression" }
  /** Gets the node corresponding to the field `arguments`. */final Arguments getArguments() { php_member_call_expression_def(this, result, _, _) }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_member_call_expression_def(this, _, result, _) }
  /** Gets the node corresponding to the field `object`. */final AstNode getObject() { php_member_call_expression_def(this, _, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_member_call_expression_def(this, result, _, _)) or (php_member_call_expression_def(this, _, result, _)) or (php_member_call_expression_def(this, _, _, result)) }
}
  /** A class representing `method_declaration` nodes. */final class MethodDeclaration extends @php_method_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "MethodDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_method_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_method_declaration_body(this, result) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_method_declaration_def(this, result, _) }
  /** Gets the node corresponding to the field `parameters`. */final FormalParameters getParameters() { php_method_declaration_def(this, _, result) }
  /** Gets the node corresponding to the field `return_type`. */final AstNode getReturnType() { php_method_declaration_return_type(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_method_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_method_declaration_attributes(this, result)) or (php_method_declaration_body(this, result)) or (php_method_declaration_def(this, result, _)) or (php_method_declaration_def(this, _, result)) or (php_method_declaration_return_type(this, result)) or (php_method_declaration_child(this, _, result)) }
}
  /** A class representing `name` tokens. */final class Name extends @php_token_name, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Name" }
}
  /** A class representing `named_label_statement` nodes. */final class NamedLabelStatement extends @php_named_label_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamedLabelStatement" }
  /** Gets the child of this node. */final Name getChild() { php_named_label_statement_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_named_label_statement_def(this, result)) }
}
  /** A class representing `named_type` nodes. */final class NamedType extends @php_named_type, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamedType" }
  /** Gets the child of this node. */final AstNode getChild() { php_named_type_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_named_type_def(this, result)) }
}
  /** A class representing `namespace_definition` nodes. */final class NamespaceDefinition extends @php_namespace_definition, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamespaceDefinition" }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_namespace_definition_body(this, result) }
  /** Gets the node corresponding to the field `name`. */final NamespaceName getName() { php_namespace_definition_name(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_namespace_definition_body(this, result)) or (php_namespace_definition_name(this, result)) }
}
  /** A class representing `namespace_name` nodes. */final class NamespaceName extends @php_namespace_name, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamespaceName" }
  /** Gets the `i`th child of this node. */final Name getChild(int i) { php_namespace_name_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_namespace_name_child(this, _, result)) }
}
  /** A class representing `namespace_use_clause` nodes. */final class NamespaceUseClause extends @php_namespace_use_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamespaceUseClause" }
  /** Gets the node corresponding to the field `alias`. */final Name getAlias() { php_namespace_use_clause_alias(this, result) }
  /** Gets the node corresponding to the field `type`. */final AstNode getType() { php_namespace_use_clause_type(this, result) }
  /** Gets the child of this node. */final AstNode getChild() { php_namespace_use_clause_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_namespace_use_clause_alias(this, result)) or (php_namespace_use_clause_type(this, result)) or (php_namespace_use_clause_def(this, result)) }
}
  /** A class representing `namespace_use_declaration` nodes. */final class NamespaceUseDeclaration extends @php_namespace_use_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamespaceUseDeclaration" }
  /** Gets the node corresponding to the field `body`. */final NamespaceUseGroup getBody() { php_namespace_use_declaration_body(this, result) }
  /** Gets the node corresponding to the field `type`. */final AstNode getType() { php_namespace_use_declaration_type(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_namespace_use_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_namespace_use_declaration_body(this, result)) or (php_namespace_use_declaration_type(this, result)) or (php_namespace_use_declaration_child(this, _, result)) }
}
  /** A class representing `namespace_use_group` nodes. */final class NamespaceUseGroup extends @php_namespace_use_group, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NamespaceUseGroup" }
  /** Gets the `i`th child of this node. */final NamespaceUseClause getChild(int i) { php_namespace_use_group_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_namespace_use_group_child(this, _, result)) }
}
  /** A class representing `nowdoc` nodes. */final class Nowdoc extends @php_nowdoc, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Nowdoc" }
  /** Gets the node corresponding to the field `end_tag`. */final HeredocEnd getEndTag() { php_nowdoc_def(this, result, _) }
  /** Gets the node corresponding to the field `identifier`. */final HeredocStart getIdentifier() { php_nowdoc_def(this, _, result) }
  /** Gets the node corresponding to the field `value`. */final NowdocBody getValue() { php_nowdoc_value(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_nowdoc_def(this, result, _)) or (php_nowdoc_def(this, _, result)) or (php_nowdoc_value(this, result)) }
}
  /** A class representing `nowdoc_body` nodes. */final class NowdocBody extends @php_nowdoc_body, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NowdocBody" }
  /** Gets the `i`th child of this node. */final NowdocString getChild(int i) { php_nowdoc_body_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_nowdoc_body_child(this, _, result)) }
}
  /** A class representing `nowdoc_string` tokens. */final class NowdocString extends @php_token_nowdoc_string, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NowdocString" }
}
  /** A class representing `null` tokens. */final class Null extends @php_token_null, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Null" }
}
  /** A class representing `nullsafe_member_access_expression` nodes. */final class NullsafeMemberAccessExpression extends @php_nullsafe_member_access_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NullsafeMemberAccessExpression" }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_nullsafe_member_access_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `object`. */final AstNode getObject() { php_nullsafe_member_access_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_nullsafe_member_access_expression_def(this, result, _)) or (php_nullsafe_member_access_expression_def(this, _, result)) }
}
  /** A class representing `nullsafe_member_call_expression` nodes. */final class NullsafeMemberCallExpression extends @php_nullsafe_member_call_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "NullsafeMemberCallExpression" }
  /** Gets the node corresponding to the field `arguments`. */final Arguments getArguments() { php_nullsafe_member_call_expression_def(this, result, _, _) }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_nullsafe_member_call_expression_def(this, _, result, _) }
  /** Gets the node corresponding to the field `object`. */final AstNode getObject() { php_nullsafe_member_call_expression_def(this, _, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_nullsafe_member_call_expression_def(this, result, _, _)) or (php_nullsafe_member_call_expression_def(this, _, result, _)) or (php_nullsafe_member_call_expression_def(this, _, _, result)) }
}
  /** A class representing `object_creation_expression` nodes. */final class ObjectCreationExpression extends @php_object_creation_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ObjectCreationExpression" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_object_creation_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_object_creation_expression_child(this, _, result)) }
}
  /** A class representing `operation` tokens. */final class Operation extends @php_token_operation, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Operation" }
}
  /** A class representing `optional_type` nodes. */final class OptionalType extends @php_optional_type, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "OptionalType" }
  /** Gets the child of this node. */final AstNode getChild() { php_optional_type_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_optional_type_def(this, result)) }
}
  /** A class representing `pair` nodes. */final class Pair extends @php_pair, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Pair" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_pair_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_pair_child(this, _, result)) }
}
  /** A class representing `parenthesized_expression` nodes. */final class ParenthesizedExpression extends @php_parenthesized_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ParenthesizedExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_parenthesized_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_parenthesized_expression_def(this, result)) }
}
  /** A class representing `php_end_tag` tokens. */final class PhpEndTag extends @php_token_php_end_tag, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PhpEndTag" }
}
  /** A class representing `php_tag` tokens. */final class PhpTag extends @php_token_php_tag, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PhpTag" }
}
  final class PrimaryExpression extends @php_primary_expression, AstNodeImpl { 
}
  /** A class representing `primitive_type` tokens. */final class PrimitiveType extends @php_token_primitive_type, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PrimitiveType" }
}
  /** A class representing `print_intrinsic` nodes. */final class PrintIntrinsic extends @php_print_intrinsic, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PrintIntrinsic" }
  /** Gets the child of this node. */final Expression getChild() { php_print_intrinsic_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_print_intrinsic_def(this, result)) }
}
  /** A class representing `program` nodes. */final class Program extends @php_program, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Program" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_program_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_program_child(this, _, result)) }
}
  /** A class representing `property_declaration` nodes. */final class PropertyDeclaration extends @php_property_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PropertyDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_property_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `type`. */final Type getType() { php_property_declaration_type(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_property_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_property_declaration_attributes(this, result)) or (php_property_declaration_type(this, result)) or (php_property_declaration_child(this, _, result)) }
}
  /** A class representing `property_element` nodes. */final class PropertyElement extends @php_property_element, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PropertyElement" }
  /** Gets the node corresponding to the field `default_value`. */final Expression getDefaultValue() { php_property_element_default_value(this, result) }
  /** Gets the node corresponding to the field `name`. */final VariableName getName() { php_property_element_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_property_element_default_value(this, result)) or (php_property_element_def(this, result)) }
}
  /** A class representing `property_hook` nodes. */final class PropertyHook extends @php_property_hook, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PropertyHook" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_property_hook_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_property_hook_body(this, result) }
  /** Gets the node corresponding to the field `final`. */final FinalModifier getFinal() { php_property_hook_final(this, result) }
  /** Gets the node corresponding to the field `parameters`. */final FormalParameters getParameters() { php_property_hook_parameters(this, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_property_hook_reference_modifier(this, result) }
  /** Gets the child of this node. */final Name getChild() { php_property_hook_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_property_hook_attributes(this, result)) or (php_property_hook_body(this, result)) or (php_property_hook_final(this, result)) or (php_property_hook_parameters(this, result)) or (php_property_hook_reference_modifier(this, result)) or (php_property_hook_def(this, result)) }
}
  /** A class representing `property_hook_list` nodes. */final class PropertyHookList extends @php_property_hook_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PropertyHookList" }
  /** Gets the `i`th child of this node. */final PropertyHook getChild(int i) { php_property_hook_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_property_hook_list_child(this, _, result)) }
}
  /** A class representing `property_promotion_parameter` nodes. */final class PropertyPromotionParameter extends @php_property_promotion_parameter, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "PropertyPromotionParameter" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_property_promotion_parameter_attributes(this, result) }
  /** Gets the node corresponding to the field `default_value`. */final Expression getDefaultValue() { php_property_promotion_parameter_default_value(this, result) }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_property_promotion_parameter_def(this, result, _) }
  /** Gets the node corresponding to the field `readonly`. */final ReadonlyModifier getReadonly() { php_property_promotion_parameter_readonly(this, result) }
  /** Gets the node corresponding to the field `type`. */final Type getType() { php_property_promotion_parameter_type(this, result) }
  /** Gets the node corresponding to the field `visibility`. */final VisibilityModifier getVisibility() { php_property_promotion_parameter_def(this, _, result) }
  /** Gets the child of this node. */final PropertyHookList getChild() { php_property_promotion_parameter_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_property_promotion_parameter_attributes(this, result)) or (php_property_promotion_parameter_default_value(this, result)) or (php_property_promotion_parameter_def(this, result, _)) or (php_property_promotion_parameter_readonly(this, result)) or (php_property_promotion_parameter_type(this, result)) or (php_property_promotion_parameter_def(this, _, result)) or (php_property_promotion_parameter_child(this, result)) }
}
  /** A class representing `qualified_name` nodes. */final class QualifiedName extends @php_qualified_name, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "QualifiedName" }
  /** Gets the node corresponding to the field `prefix`. */final AstNode getPrefix(int i) { php_qualified_name_prefix(this, i, result) }
  /** Gets the child of this node. */final Name getChild() { php_qualified_name_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_qualified_name_prefix(this, _, result)) or (php_qualified_name_def(this, result)) }
}
  /** A class representing `readonly_modifier` tokens. */final class ReadonlyModifier extends @php_token_readonly_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ReadonlyModifier" }
}
  /** A class representing `reference_assignment_expression` nodes. */final class ReferenceAssignmentExpression extends @php_reference_assignment_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ReferenceAssignmentExpression" }
  /** Gets the node corresponding to the field `left`. */final AstNode getLeft() { php_reference_assignment_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `right`. */final Expression getRight() { php_reference_assignment_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_reference_assignment_expression_def(this, result, _)) or (php_reference_assignment_expression_def(this, _, result)) }
}
  /** A class representing `reference_modifier` tokens. */final class ReferenceModifier extends @php_token_reference_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ReferenceModifier" }
}
  /** A class representing `relative_name` nodes. */final class RelativeName extends @php_relative_name, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "RelativeName" }
  /** Gets the node corresponding to the field `prefix`. */final AstNode getPrefix(int i) { php_relative_name_prefix(this, i, result) }
  /** Gets the child of this node. */final Name getChild() { php_relative_name_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_relative_name_prefix(this, _, result)) or (php_relative_name_def(this, result)) }
}
  /** A class representing `relative_scope` tokens. */final class RelativeScope extends @php_token_relative_scope, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "RelativeScope" }
}
  /** A class representing `require_expression` nodes. */final class RequireExpression extends @php_require_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "RequireExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_require_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_require_expression_def(this, result)) }
}
  /** A class representing `require_once_expression` nodes. */final class RequireOnceExpression extends @php_require_once_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "RequireOnceExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_require_once_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_require_once_expression_def(this, result)) }
}
  /** A class representing `return_statement` nodes. */final class ReturnStatement extends @php_return_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ReturnStatement" }
  /** Gets the child of this node. */final Expression getChild() { php_return_statement_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_return_statement_child(this, result)) }
}
  /** A class representing `scoped_call_expression` nodes. */final class ScopedCallExpression extends @php_scoped_call_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ScopedCallExpression" }
  /** Gets the node corresponding to the field `arguments`. */final Arguments getArguments() { php_scoped_call_expression_def(this, result, _, _) }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_scoped_call_expression_def(this, _, result, _) }
  /** Gets the node corresponding to the field `scope`. */final AstNode getScope() { php_scoped_call_expression_def(this, _, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_scoped_call_expression_def(this, result, _, _)) or (php_scoped_call_expression_def(this, _, result, _)) or (php_scoped_call_expression_def(this, _, _, result)) }
}
  /** A class representing `scoped_property_access_expression` nodes. */final class ScopedPropertyAccessExpression extends @php_scoped_property_access_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ScopedPropertyAccessExpression" }
  /** Gets the node corresponding to the field `name`. */final AstNode getName() { php_scoped_property_access_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `scope`. */final AstNode getScope() { php_scoped_property_access_expression_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_scoped_property_access_expression_def(this, result, _)) or (php_scoped_property_access_expression_def(this, _, result)) }
}
  /** A class representing `sequence_expression` nodes. */final class SequenceExpression extends @php_sequence_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "SequenceExpression" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_sequence_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_sequence_expression_child(this, _, result)) }
}
  /** A class representing `shell_command_expression` nodes. */final class ShellCommandExpression extends @php_shell_command_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ShellCommandExpression" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_shell_command_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_shell_command_expression_child(this, _, result)) }
}
  /** A class representing `simple_parameter` nodes. */final class SimpleParameter extends @php_simple_parameter, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "SimpleParameter" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_simple_parameter_attributes(this, result) }
  /** Gets the node corresponding to the field `default_value`. */final Expression getDefaultValue() { php_simple_parameter_default_value(this, result) }
  /** Gets the node corresponding to the field `name`. */final VariableName getName() { php_simple_parameter_def(this, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_simple_parameter_reference_modifier(this, result) }
  /** Gets the node corresponding to the field `type`. */final Type getType() { php_simple_parameter_type(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_simple_parameter_attributes(this, result)) or (php_simple_parameter_default_value(this, result)) or (php_simple_parameter_def(this, result)) or (php_simple_parameter_reference_modifier(this, result)) or (php_simple_parameter_type(this, result)) }
}
  final class Statement extends @php_statement, AstNodeImpl { 
}
  /** A class representing `static_modifier` tokens. */final class StaticModifier extends @php_token_static_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "StaticModifier" }
}
  /** A class representing `static_variable_declaration` nodes. */final class StaticVariableDeclaration extends @php_static_variable_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "StaticVariableDeclaration" }
  /** Gets the node corresponding to the field `name`. */final VariableName getName() { php_static_variable_declaration_def(this, result) }
  /** Gets the node corresponding to the field `value`. */final Expression getValue() { php_static_variable_declaration_value(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_static_variable_declaration_def(this, result)) or (php_static_variable_declaration_value(this, result)) }
}
  /** A class representing `string` nodes. */final class String extends @php_string__, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "String" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_string_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_string_child(this, _, result)) }
}
  /** A class representing `string_content` tokens. */final class StringContent extends @php_token_string_content, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "StringContent" }
}
  /** A class representing `subscript_expression` nodes. */final class SubscriptExpression extends @php_subscript_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "SubscriptExpression" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_subscript_expression_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_subscript_expression_child(this, _, result)) }
}
  /** A class representing `switch_block` nodes. */final class SwitchBlock extends @php_switch_block, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "SwitchBlock" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_switch_block_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_switch_block_child(this, _, result)) }
}
  /** A class representing `switch_statement` nodes. */final class SwitchStatement extends @php_switch_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "SwitchStatement" }
  /** Gets the node corresponding to the field `body`. */final SwitchBlock getBody() { php_switch_statement_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_switch_statement_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_switch_statement_def(this, result, _)) or (php_switch_statement_def(this, _, result)) }
}
  /** A class representing `text` tokens. */final class Text extends @php_token_text, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "Text" }
}
  /** A class representing `text_interpolation` nodes. */final class TextInterpolation extends @php_text_interpolation, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "TextInterpolation" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_text_interpolation_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_text_interpolation_child(this, _, result)) }
}
  /** A class representing `throw_expression` nodes. */final class ThrowExpression extends @php_throw_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "ThrowExpression" }
  /** Gets the child of this node. */final Expression getChild() { php_throw_expression_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_throw_expression_def(this, result)) }
}
  /** A class representing `trait_declaration` nodes. */final class TraitDeclaration extends @php_trait_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "TraitDeclaration" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_trait_declaration_attributes(this, result) }
  /** Gets the node corresponding to the field `body`. */final DeclarationList getBody() { php_trait_declaration_def(this, result, _) }
  /** Gets the node corresponding to the field `name`. */final Name getName() { php_trait_declaration_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_trait_declaration_attributes(this, result)) or (php_trait_declaration_def(this, result, _)) or (php_trait_declaration_def(this, _, result)) }
}
  /** A class representing `try_statement` nodes. */final class TryStatement extends @php_try_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "TryStatement" }
  /** Gets the node corresponding to the field `body`. */final CompoundStatement getBody() { php_try_statement_def(this, result) }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_try_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_try_statement_def(this, result)) or (php_try_statement_child(this, _, result)) }
}
  final class Type extends @php_type__, AstNodeImpl { 
}
  /** A class representing `type_list` nodes. */final class TypeList extends @php_type_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "TypeList" }
  /** Gets the `i`th child of this node. */final NamedType getChild(int i) { php_type_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_type_list_child(this, _, result)) }
}
  /** A class representing `unary_op_expression` nodes. */final class UnaryOpExpression extends @php_unary_op_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UnaryOpExpression" }
  /** Gets the node corresponding to the field `argument`. */final Expression getArgument() { php_unary_op_expression_argument(this, result) }
  /** Gets the node corresponding to the field `operator`. */final AstNode getOperator() { php_unary_op_expression_operator(this, result) }
  /** Gets the child of this node. */final Integer getChild() { php_unary_op_expression_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_unary_op_expression_argument(this, result)) or (php_unary_op_expression_operator(this, result)) or (php_unary_op_expression_child(this, result)) }
}
  /** A class representing `union_type` nodes. */final class UnionType extends @php_union_type, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UnionType" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_union_type_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_union_type_child(this, _, result)) }
}
  /** A class representing `unset_statement` nodes. */final class UnsetStatement extends @php_unset_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UnsetStatement" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_unset_statement_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_unset_statement_child(this, _, result)) }
}
  /** A class representing `update_expression` nodes. */final class UpdateExpression extends @php_update_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UpdateExpression" }
  /** Gets the node corresponding to the field `argument`. */final AstNode getArgument() { php_update_expression_def(this, result, _) }
  /** Gets the node corresponding to the field `operator`. */final string getOperator() { exists(int value | php_update_expression_def(this, _, value) | ((result = "++") and (value = 0)) or ((result = "--") and (value = 1))) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_update_expression_def(this, result, _)) }
}
  /** A class representing `use_as_clause` nodes. */final class UseAsClause extends @php_use_as_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UseAsClause" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_use_as_clause_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_use_as_clause_child(this, _, result)) }
}
  /** A class representing `use_declaration` nodes. */final class UseDeclaration extends @php_use_declaration, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UseDeclaration" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_use_declaration_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_use_declaration_child(this, _, result)) }
}
  /** A class representing `use_instead_of_clause` nodes. */final class UseInsteadOfClause extends @php_use_instead_of_clause, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UseInsteadOfClause" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_use_instead_of_clause_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_use_instead_of_clause_child(this, _, result)) }
}
  /** A class representing `use_list` nodes. */final class UseList extends @php_use_list, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "UseList" }
  /** Gets the `i`th child of this node. */final AstNode getChild(int i) { php_use_list_child(this, i, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_use_list_child(this, _, result)) }
}
  /** A class representing `var_modifier` tokens. */final class VarModifier extends @php_token_var_modifier, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VarModifier" }
}
  /** A class representing `variable_name` nodes. */final class VariableName extends @php_variable_name, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VariableName" }
  /** Gets the child of this node. */final Name getChild() { php_variable_name_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_variable_name_def(this, result)) }
}
  /** A class representing `variadic_parameter` nodes. */final class VariadicParameter extends @php_variadic_parameter, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VariadicParameter" }
  /** Gets the node corresponding to the field `attributes`. */final AttributeList getAttributes() { php_variadic_parameter_attributes(this, result) }
  /** Gets the node corresponding to the field `name`. */final VariableName getName() { php_variadic_parameter_def(this, result) }
  /** Gets the node corresponding to the field `reference_modifier`. */final ReferenceModifier getReferenceModifier() { php_variadic_parameter_reference_modifier(this, result) }
  /** Gets the node corresponding to the field `type`. */final Type getType() { php_variadic_parameter_type(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_variadic_parameter_attributes(this, result)) or (php_variadic_parameter_def(this, result)) or (php_variadic_parameter_reference_modifier(this, result)) or (php_variadic_parameter_type(this, result)) }
}
  /** A class representing `variadic_placeholder` tokens. */final class VariadicPlaceholder extends @php_token_variadic_placeholder, TokenImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VariadicPlaceholder" }
}
  /** A class representing `variadic_unpacking` nodes. */final class VariadicUnpacking extends @php_variadic_unpacking, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VariadicUnpacking" }
  /** Gets the child of this node. */final Expression getChild() { php_variadic_unpacking_def(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_variadic_unpacking_def(this, result)) }
}
  /** A class representing `visibility_modifier` nodes. */final class VisibilityModifier extends @php_visibility_modifier, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "VisibilityModifier" }
  /** Gets the child of this node. */final Operation getChild() { php_visibility_modifier_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_visibility_modifier_child(this, result)) }
}
  /** A class representing `while_statement` nodes. */final class WhileStatement extends @php_while_statement, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "WhileStatement" }
  /** Gets the node corresponding to the field `body`. */final AstNode getBody() { php_while_statement_def(this, result, _) }
  /** Gets the node corresponding to the field `condition`. */final ParenthesizedExpression getCondition() { php_while_statement_def(this, _, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_while_statement_def(this, result, _)) or (php_while_statement_def(this, _, result)) }
}
  /** A class representing `yield_expression` nodes. */final class YieldExpression extends @php_yield_expression, AstNodeImpl { 
  /** Gets the name of the primary QL class for this element. */final override string getAPrimaryQlClass() { result = "YieldExpression" }
  /** Gets the child of this node. */final AstNode getChild() { php_yield_expression_child(this, result) }
  /** Gets a field or child node of this node. */final override AstNode getAFieldOrChild() { (php_yield_expression_child(this, result)) }
}
  /** Provides predicates for mapping AST nodes to their named children. */module PrintAst { 
  /** Gets a child of `node` returned by the member predicate with the given `name`. If the predicate takes an index argument, `i` is bound to that index, otherwise `i` is `-1` (which is never a valid index). */AstNode getChild(AstNode node, string name, int i) { ((result = node.(AnonymousClass).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(AnonymousClass).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(AnonymousClass).getChild(i)) and (name = "getChild")) or ((result = node.(AnonymousFunction).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(AnonymousFunction).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(AnonymousFunction).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(AnonymousFunction).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(AnonymousFunction).getReturnType()) and (i = -1) and (name = "getReturnType")) or ((result = node.(AnonymousFunction).getStaticModifier()) and (i = -1) and (name = "getStaticModifier")) or ((result = node.(AnonymousFunction).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(AnonymousFunctionUseClause).getChild(i)) and (name = "getChild")) or ((result = node.(Argument).getName()) and (i = -1) and (name = "getName")) or ((result = node.(Argument).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(Argument).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(Arguments).getChild(i)) and (name = "getChild")) or ((result = node.(ArrayCreationExpression).getChild(i)) and (name = "getChild")) or ((result = node.(ArrayElementInitializer).getChild(i)) and (name = "getChild")) or ((result = node.(ArrowFunction).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(ArrowFunction).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ArrowFunction).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(ArrowFunction).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(ArrowFunction).getReturnType()) and (i = -1) and (name = "getReturnType")) or ((result = node.(ArrowFunction).getStaticModifier()) and (i = -1) and (name = "getStaticModifier")) or ((result = node.(AssignmentExpression).getLeft()) and (i = -1) and (name = "getLeft")) or ((result = node.(AssignmentExpression).getRight()) and (i = -1) and (name = "getRight")) or ((result = node.(Attribute).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(Attribute).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(AttributeGroup).getChild(i)) and (name = "getChild")) or ((result = node.(AttributeList).getChild(i)) and (name = "getChild")) or ((result = node.(AugmentedAssignmentExpression).getLeft()) and (i = -1) and (name = "getLeft")) or ((result = node.(AugmentedAssignmentExpression).getRight()) and (i = -1) and (name = "getRight")) or ((result = node.(BaseClause).getChild(i)) and (name = "getChild")) or ((result = node.(BinaryExpression).getLeft()) and (i = -1) and (name = "getLeft")) or ((result = node.(BinaryExpression).getRight()) and (i = -1) and (name = "getRight")) or ((result = node.(BreakStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ByRef).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(CaseStatement).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(CaseStatement).getChild(i)) and (name = "getChild")) or ((result = node.(CastExpression).getType()) and (i = -1) and (name = "getType")) or ((result = node.(CastExpression).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(CatchClause).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(CatchClause).getName()) and (i = -1) and (name = "getName")) or ((result = node.(CatchClause).getType()) and (i = -1) and (name = "getType")) or ((result = node.(ClassConstantAccessExpression).getChild(i)) and (name = "getChild")) or ((result = node.(ClassDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(ClassDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ClassDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(ClassDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(ClassInterfaceClause).getChild(i)) and (name = "getChild")) or ((result = node.(CloneExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ColonBlock).getChild(i)) and (name = "getChild")) or ((result = node.(CompoundStatement).getChild(i)) and (name = "getChild")) or ((result = node.(ConditionalExpression).getAlternative()) and (i = -1) and (name = "getAlternative")) or ((result = node.(ConditionalExpression).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ConditionalExpression).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(ConstDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(ConstDeclaration).getType()) and (i = -1) and (name = "getType")) or ((result = node.(ConstDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(ConstElement).getChild(i)) and (name = "getChild")) or ((result = node.(ContinueStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(DeclarationList).getChild(i)) and (name = "getChild")) or ((result = node.(DeclareDirective).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(DeclareStatement).getChild(i)) and (name = "getChild")) or ((result = node.(DefaultStatement).getChild(i)) and (name = "getChild")) or ((result = node.(DisjunctiveNormalFormType).getChild(i)) and (name = "getChild")) or ((result = node.(DoStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(DoStatement).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(DynamicVariableName).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(EchoStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ElseClause).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ElseIfClause).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ElseIfClause).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(EncapsedString).getChild(i)) and (name = "getChild")) or ((result = node.(EnumCase).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(EnumCase).getName()) and (i = -1) and (name = "getName")) or ((result = node.(EnumCase).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(EnumDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(EnumDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(EnumDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(EnumDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(EnumDeclarationList).getChild(i)) and (name = "getChild")) or ((result = node.(ErrorSuppressionExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ExitStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ExpressionStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(FinallyClause).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ForStatement).getBody(i)) and (name = "getBody")) or ((result = node.(ForStatement).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(ForStatement).getInitialize()) and (i = -1) and (name = "getInitialize")) or ((result = node.(ForStatement).getUpdate()) and (i = -1) and (name = "getUpdate")) or ((result = node.(ForeachStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(ForeachStatement).getChild(i)) and (name = "getChild")) or ((result = node.(FormalParameters).getChild(i)) and (name = "getChild")) or ((result = node.(FunctionCallExpression).getArguments()) and (i = -1) and (name = "getArguments")) or ((result = node.(FunctionCallExpression).getFunction()) and (i = -1) and (name = "getFunction")) or ((result = node.(FunctionDefinition).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(FunctionDefinition).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(FunctionDefinition).getName()) and (i = -1) and (name = "getName")) or ((result = node.(FunctionDefinition).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(FunctionDefinition).getReturnType()) and (i = -1) and (name = "getReturnType")) or ((result = node.(FunctionDefinition).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(FunctionStaticDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(GlobalDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(GotoStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(Heredoc).getEndTag()) and (i = -1) and (name = "getEndTag")) or ((result = node.(Heredoc).getIdentifier()) and (i = -1) and (name = "getIdentifier")) or ((result = node.(Heredoc).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(HeredocBody).getChild(i)) and (name = "getChild")) or ((result = node.(IfStatement).getAlternative(i)) and (name = "getAlternative")) or ((result = node.(IfStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(IfStatement).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(IncludeExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(IncludeOnceExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(InterfaceDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(InterfaceDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(InterfaceDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(InterfaceDeclaration).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(IntersectionType).getChild(i)) and (name = "getChild")) or ((result = node.(ListLiteral).getChild(i)) and (name = "getChild")) or ((result = node.(MatchBlock).getChild(i)) and (name = "getChild")) or ((result = node.(MatchConditionList).getChild(i)) and (name = "getChild")) or ((result = node.(MatchConditionalExpression).getConditionalExpressions()) and (i = -1) and (name = "getConditionalExpressions")) or ((result = node.(MatchConditionalExpression).getReturnExpression()) and (i = -1) and (name = "getReturnExpression")) or ((result = node.(MatchDefaultExpression).getReturnExpression()) and (i = -1) and (name = "getReturnExpression")) or ((result = node.(MatchExpression).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(MatchExpression).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(MemberAccessExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(MemberAccessExpression).getObject()) and (i = -1) and (name = "getObject")) or ((result = node.(MemberCallExpression).getArguments()) and (i = -1) and (name = "getArguments")) or ((result = node.(MemberCallExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(MemberCallExpression).getObject()) and (i = -1) and (name = "getObject")) or ((result = node.(MethodDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(MethodDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(MethodDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(MethodDeclaration).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(MethodDeclaration).getReturnType()) and (i = -1) and (name = "getReturnType")) or ((result = node.(MethodDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(NamedLabelStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(NamedType).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(NamespaceDefinition).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(NamespaceDefinition).getName()) and (i = -1) and (name = "getName")) or ((result = node.(NamespaceName).getChild(i)) and (name = "getChild")) or ((result = node.(NamespaceUseClause).getAlias()) and (i = -1) and (name = "getAlias")) or ((result = node.(NamespaceUseClause).getType()) and (i = -1) and (name = "getType")) or ((result = node.(NamespaceUseClause).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(NamespaceUseDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(NamespaceUseDeclaration).getType()) and (i = -1) and (name = "getType")) or ((result = node.(NamespaceUseDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(NamespaceUseGroup).getChild(i)) and (name = "getChild")) or ((result = node.(Nowdoc).getEndTag()) and (i = -1) and (name = "getEndTag")) or ((result = node.(Nowdoc).getIdentifier()) and (i = -1) and (name = "getIdentifier")) or ((result = node.(Nowdoc).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(NowdocBody).getChild(i)) and (name = "getChild")) or ((result = node.(NullsafeMemberAccessExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(NullsafeMemberAccessExpression).getObject()) and (i = -1) and (name = "getObject")) or ((result = node.(NullsafeMemberCallExpression).getArguments()) and (i = -1) and (name = "getArguments")) or ((result = node.(NullsafeMemberCallExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(NullsafeMemberCallExpression).getObject()) and (i = -1) and (name = "getObject")) or ((result = node.(ObjectCreationExpression).getChild(i)) and (name = "getChild")) or ((result = node.(OptionalType).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(Pair).getChild(i)) and (name = "getChild")) or ((result = node.(ParenthesizedExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(PrintIntrinsic).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(Program).getChild(i)) and (name = "getChild")) or ((result = node.(PropertyDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(PropertyDeclaration).getType()) and (i = -1) and (name = "getType")) or ((result = node.(PropertyDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(PropertyElement).getDefaultValue()) and (i = -1) and (name = "getDefaultValue")) or ((result = node.(PropertyElement).getName()) and (i = -1) and (name = "getName")) or ((result = node.(PropertyHook).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(PropertyHook).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(PropertyHook).getFinal()) and (i = -1) and (name = "getFinal")) or ((result = node.(PropertyHook).getParameters()) and (i = -1) and (name = "getParameters")) or ((result = node.(PropertyHook).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(PropertyHook).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(PropertyHookList).getChild(i)) and (name = "getChild")) or ((result = node.(PropertyPromotionParameter).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(PropertyPromotionParameter).getDefaultValue()) and (i = -1) and (name = "getDefaultValue")) or ((result = node.(PropertyPromotionParameter).getName()) and (i = -1) and (name = "getName")) or ((result = node.(PropertyPromotionParameter).getReadonly()) and (i = -1) and (name = "getReadonly")) or ((result = node.(PropertyPromotionParameter).getType()) and (i = -1) and (name = "getType")) or ((result = node.(PropertyPromotionParameter).getVisibility()) and (i = -1) and (name = "getVisibility")) or ((result = node.(PropertyPromotionParameter).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(QualifiedName).getPrefix(i)) and (name = "getPrefix")) or ((result = node.(QualifiedName).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ReferenceAssignmentExpression).getLeft()) and (i = -1) and (name = "getLeft")) or ((result = node.(ReferenceAssignmentExpression).getRight()) and (i = -1) and (name = "getRight")) or ((result = node.(RelativeName).getPrefix(i)) and (name = "getPrefix")) or ((result = node.(RelativeName).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(RequireExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(RequireOnceExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ReturnStatement).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(ScopedCallExpression).getArguments()) and (i = -1) and (name = "getArguments")) or ((result = node.(ScopedCallExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(ScopedCallExpression).getScope()) and (i = -1) and (name = "getScope")) or ((result = node.(ScopedPropertyAccessExpression).getName()) and (i = -1) and (name = "getName")) or ((result = node.(ScopedPropertyAccessExpression).getScope()) and (i = -1) and (name = "getScope")) or ((result = node.(SequenceExpression).getChild(i)) and (name = "getChild")) or ((result = node.(ShellCommandExpression).getChild(i)) and (name = "getChild")) or ((result = node.(SimpleParameter).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(SimpleParameter).getDefaultValue()) and (i = -1) and (name = "getDefaultValue")) or ((result = node.(SimpleParameter).getName()) and (i = -1) and (name = "getName")) or ((result = node.(SimpleParameter).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(SimpleParameter).getType()) and (i = -1) and (name = "getType")) or ((result = node.(StaticVariableDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(StaticVariableDeclaration).getValue()) and (i = -1) and (name = "getValue")) or ((result = node.(String).getChild(i)) and (name = "getChild")) or ((result = node.(SubscriptExpression).getChild(i)) and (name = "getChild")) or ((result = node.(SwitchBlock).getChild(i)) and (name = "getChild")) or ((result = node.(SwitchStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(SwitchStatement).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(TextInterpolation).getChild(i)) and (name = "getChild")) or ((result = node.(ThrowExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(TraitDeclaration).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(TraitDeclaration).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(TraitDeclaration).getName()) and (i = -1) and (name = "getName")) or ((result = node.(TryStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(TryStatement).getChild(i)) and (name = "getChild")) or ((result = node.(TypeList).getChild(i)) and (name = "getChild")) or ((result = node.(UnaryOpExpression).getArgument()) and (i = -1) and (name = "getArgument")) or ((result = node.(UnaryOpExpression).getOperator()) and (i = -1) and (name = "getOperator")) or ((result = node.(UnaryOpExpression).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(UnionType).getChild(i)) and (name = "getChild")) or ((result = node.(UnsetStatement).getChild(i)) and (name = "getChild")) or ((result = node.(UpdateExpression).getArgument()) and (i = -1) and (name = "getArgument")) or ((result = node.(UseAsClause).getChild(i)) and (name = "getChild")) or ((result = node.(UseDeclaration).getChild(i)) and (name = "getChild")) or ((result = node.(UseInsteadOfClause).getChild(i)) and (name = "getChild")) or ((result = node.(UseList).getChild(i)) and (name = "getChild")) or ((result = node.(VariableName).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(VariadicParameter).getAttributes()) and (i = -1) and (name = "getAttributes")) or ((result = node.(VariadicParameter).getName()) and (i = -1) and (name = "getName")) or ((result = node.(VariadicParameter).getReferenceModifier()) and (i = -1) and (name = "getReferenceModifier")) or ((result = node.(VariadicParameter).getType()) and (i = -1) and (name = "getType")) or ((result = node.(VariadicUnpacking).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(VisibilityModifier).getChild()) and (i = -1) and (name = "getChild")) or ((result = node.(WhileStatement).getBody()) and (i = -1) and (name = "getBody")) or ((result = node.(WhileStatement).getCondition()) and (i = -1) and (name = "getCondition")) or ((result = node.(YieldExpression).getChild()) and (i = -1) and (name = "getChild")) }
}
}

