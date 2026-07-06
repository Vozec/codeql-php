#!/usr/bin/env bash
# CVE corpus harness: build a CodeQL DB from the PoC files under cve/, analyze with the PHP security
# suite, and report which CVEs are detected. Each PoC marks its vulnerable line with a comment
#   // ruleid: <query-id>       (e.g. `// ruleid: php/sql-injection`)
# on the line ABOVE the sink; detection is scored with +/-1 line tolerance (same convention as bench/).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CODEQL="$REPO/.tooling/codeql/codeql"
SRC="$REPO/cve"
DB="/tmp/cve-db"
SARIF="/tmp/cve.sarif"

# --- stage a minimal extractor pack (release binary + dbscheme + tools) --------------------------
EXT="/tmp/cve-ext"
rm -rf "$EXT"; mkdir -p "$EXT/tools/linux64"
cp "$REPO/php/codeql-extractor.yml" "$EXT/"
cp "$REPO/php/ql/lib/php.dbscheme" "$REPO/php/ql/lib/php.dbscheme.stats" "$EXT/"
cp "$REPO/target/release/codeql-extractor-php" "$EXT/tools/linux64/extractor"
cp -r "$REPO/php/tools/"* "$EXT/tools/" 2>/dev/null || true

echo ">> extracting cve/ ..."
rm -rf "$DB"
"$CODEQL" database create "$DB" --language=php --source-root="$SRC" \
  --search-path="$EXT" --threads=4 2>&1 | grep -iE "successfully|error|fatal" | tail -1

echo ">> analyzing ..."
"$CODEQL" database analyze "$DB" "$REPO/php/ql/src/codeql-suites/php-security-extended.qls" \
  --format=sarifv2.1.0 --output="$SARIF" --search-path="$REPO/php" --threads=4 2>&1 \
  | grep -iE "error|fatal" | tail -2 || true

python3 "$SRC/score.py" "$SARIF" "$SRC"
