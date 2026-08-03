#!/usr/bin/env bash
# Fast iterate on a query while tuning: extract ONE module (not the whole app) once,
# then analyse repeatedly hitting the disk cache (no --rerun). 10x faster than full-app.
#   fastscan.sh <source-dir> <query.ql> [more.ql ...]
# Env: TOOL (codeql-php root), EXT (built extractor pack). Re-extracts only if SRC changed.
set -eu
TOOL="${TOOL:-$(cd "$(dirname "$0")/.." && pwd)}"
EXT="${EXT:-/tmp/php-ext}"
SRC="$1"; shift
DB="/tmp/fastscan-$(echo "$SRC" | tr '/ ' '__').db"
CODEQL="$TOOL/.tooling/codeql/codeql"
# build extractor pack if missing
if [ ! -f "$EXT/tools/linux64/extractor" ]; then
  ( cd "$TOOL/php/extractor" && cargo build --release >/dev/null )
  mkdir -p "$EXT/tools/linux64"
  cp "$TOOL/php/codeql-extractor.yml" "$TOOL/php/ql/lib/php.dbscheme" "$TOOL/php/ql/lib/php.dbscheme.stats" "$EXT/"
  cp "$TOOL/target/release/codeql-extractor-php" "$EXT/tools/linux64/extractor"
  cp -r "$TOOL/php/tools/"* "$EXT/tools/" 2>/dev/null || true
fi
# extract once (skip if the DB is newer than the source tree)
if [ ! -d "$DB" ] || [ -n "$(find "$SRC" -newer "$DB" -name '*.php' -print -quit 2>/dev/null)" ]; then
  echo ">> extracting $(find "$SRC" -name '*.php'|wc -l) files -> $DB"
  "$CODEQL" database create "$DB" --language=php --source-root="$SRC" --search-path="$EXT" --ram=8000 --threads=4 --overwrite >/dev/null 2>&1
fi
# analyse WITHOUT --rerun so the disk cache is reused across edits
echo ">> analysing (cache on)"; t=$(date +%s)
"$CODEQL" database analyze "$DB" "$@" --format=csv --output=/tmp/fastscan.csv \
  --search-path="$TOOL/php" --additional-packs="$TOOL" --threads=4 --ram=8000 --max-disk-cache=8000 >/dev/null 2>&1
echo ">> $(($(date +%s)-t))s | $(wc -l </tmp/fastscan.csv) findings -> /tmp/fastscan.csv"
