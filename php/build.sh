#!/usr/bin/env bash
# Reproducible build for the CodeQL PHP extractor + library packaging.
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../codeql/php
REPO="$(cd "$HERE/.." && pwd)"                          # .../codeql
PLATFORM="${CODEQL_PLATFORM:-linux64}"

echo ">> [1/4] Building Rust extractor (release)"
( cd "$REPO" && cargo build --release -p codeql-extractor-php )

echo ">> [2/4] Generating dbscheme + AST library from tree-sitter-php grammar"
mkdir -p "$HERE/ql/lib/codeql/php/ast/internal"
"$REPO/target/release/codeql-extractor-php" generate \
  --dbscheme "$HERE/ql/lib/php.dbscheme" \
  --library  "$HERE/ql/lib/codeql/php/ast/internal/TreeSitter.qll"

echo ">> [3/4] Packaging extractor pack (binary + dbscheme at pack root)"
mkdir -p "$HERE/tools/$PLATFORM"
cp "$REPO/target/release/codeql-extractor-php" "$HERE/tools/$PLATFORM/extractor"
chmod +x "$HERE/tools/$PLATFORM/extractor"
cp "$HERE/ql/lib/php.dbscheme" "$HERE/php.dbscheme"

echo ">> [4/4] Done."
echo "   dbscheme:  $HERE/ql/lib/php.dbscheme"
echo "   AST lib:   $HERE/ql/lib/codeql/php/ast/internal/TreeSitter.qll"
echo "   extractor: $HERE/tools/$PLATFORM/extractor"
echo
echo "NOTE: regenerate stats after schema changes with:"
echo "  codeql dataset measure --output $HERE/ql/lib/php.dbscheme.stats <db>/db-php"
