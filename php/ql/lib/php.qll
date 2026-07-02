/**
 * Provides classes for working with PHP programs.
 *
 * This is the top-level import for the PHP CodeQL library. For now it exposes the
 * raw tree-sitter AST (Phase 1). Higher-level wrappers (AST, CFG, dataflow) are
 * layered on top in later phases.
 */

import codeql.Locations
import codeql.php.ast.internal.TreeSitter
import codeql.php.AST
import codeql.php.controlflow.ControlFlowGraph
import codeql.php.controlflow.BasicBlocks
import codeql.php.dataflow.DataFlow
