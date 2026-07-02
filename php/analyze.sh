#!/usr/bin/env bash
#
# CodeQL PHP security scanner — one-shot analysis of a PHP codebase.
#
# Usage:
#   php/analyze.sh <php-source-dir> [output.sarif]
#
# Produces a SARIF report and prints a readable summary of findings by CWE.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../codeql/php
REPO="$(cd "$HERE/.." && pwd)"                          # .../codeql
CODEQL="$(cd "$HERE/../../tools/codeql" && pwd)/codeql" # .../tools/codeql/codeql

if [ $# -lt 1 ]; then
  echo "Usage: $0 <php-source-dir> [output.sarif]" >&2
  exit 2
fi

SRC="$1"
OUT="${2:-php-results.sarif}"
DB="$(mktemp -d)/phpdb"

echo ">> Building CodeQL database from $SRC"
"$CODEQL" database create "$DB" --language=php --source-root="$SRC" --search-path="$HERE" >/dev/null

echo ">> Running PHP security suite"
"$CODEQL" database analyze "$DB" "$HERE/ql/src/codeql-suites/php-security.qls" \
  --format=sarifv2.1.0 --output="$OUT" --search-path="$HERE" --additional-packs="$REPO" \
  --threads=0 >/dev/null

CSV="$(mktemp)"
"$CODEQL" database analyze "$DB" "$HERE/ql/src/codeql-suites/php-security.qls" \
  --format=csv --output="$CSV" --search-path="$HERE" --additional-packs="$REPO" \
  --threads=0 --rerun >/dev/null

echo
echo "==================== SUMMARY ===================="
TOTAL="$(wc -l < "$CSV" | tr -d ' ')"
echo "Total findings: $TOTAL"
echo "By rule:"
cut -d',' -f1 "$CSV" | sort | uniq -c | sort -rn
echo
echo "SARIF report: $OUT"
echo "================================================="
