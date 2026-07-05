#!/usr/bin/env bash
# One-command recall/precision benchmark against the semgrep-rules PHP corpus.
#   bench/run.sh [--extract] [--corpus DIR]
# Prints "RECALL n/232 (p%) | FP-on-ok f/176" plus a per-category breakdown, and diffs
# against bench/baseline.txt (committed) so a recall regression is visible immediately.
#
# Reuses the extracted DB in $DB unless --extract is passed (or the DB is missing). The
# extractor pack is rebuilt into $EXT from target/release so model/QL edits are picked up
# without re-extracting the corpus (analysis reads the local pack via --search-path).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODEQL="$ROOT/.tooling/codeql/codeql"
CORPUS="${CORPUS:-/tmp/semgrep-rules/php}"
EXT="${EXT:-/tmp/php-ext}"
DB="${DB:-/tmp/sr-db}"
CSV="${CSV:-/tmp/sr-bench.csv}"
EXTRACT=0
while [ $# -gt 0 ]; do case "$1" in --extract) EXTRACT=1;; --corpus) CORPUS="$2"; shift;; esac; shift; done

# 1. Corpus
if [ ! -d "$CORPUS" ]; then
  echo ">> cloning semgrep-rules corpus..."
  git clone --depth 1 https://github.com/semgrep/semgrep-rules.git "$(dirname "$CORPUS")" >/dev/null 2>&1
fi

# 2. Extractor pack (rebuild from target/release; cheap, keeps models in sync)
echo ">> refreshing extractor pack -> $EXT"
( cd "$ROOT/php/extractor" && cargo build --release >/dev/null 2>&1 ) || true
rm -rf "$EXT"; mkdir -p "$EXT/tools/linux64"
cp "$ROOT/php/codeql-extractor.yml" "$EXT/"
cp "$ROOT/php/ql/lib/php.dbscheme" "$ROOT/php/ql/lib/php.dbscheme.stats" "$EXT/"
cp "$ROOT/target/release/codeql-extractor-php" "$EXT/tools/linux64/extractor"
cp -r "$ROOT/php/tools/"* "$EXT/tools/" 2>/dev/null || true

# 3. Extract (only if asked or DB missing)
if [ "$EXTRACT" = 1 ] || [ ! -d "$DB" ]; then
  echo ">> extracting corpus -> $DB"
  rm -rf "$DB"
  "$CODEQL" database create "$DB" --language=php --source-root="$CORPUS" --search-path="$EXT" --threads=4 >/dev/null 2>&1
fi

# 4. Analyze
echo ">> analyzing (php-security-extended)"
"$CODEQL" database analyze "$DB" "$ROOT/php/ql/src/codeql-suites/php-security-extended.qls" \
  --format=csv --output="$CSV" --search-path="$ROOT/php" --additional-packs="$ROOT" \
  --threads=4 --rerun >/dev/null 2>&1

# 5. Score + baseline diff
echo ">> score:"
OUT="$(python3 "$ROOT/bench/score_semgrep.py" "$CSV" "$CORPUS")"
echo "$OUT"
BASE="$ROOT/bench/baseline.txt"
if [ -f "$BASE" ]; then
  echo ">> vs baseline:"
  diff <(grep -oE 'RECALL [0-9]+' "$BASE") <(echo "$OUT" | grep -oE 'RECALL [0-9]+') >/dev/null \
    && echo "   recall unchanged" || echo "   recall CHANGED (baseline: $(grep RECALL "$BASE"))"
fi
