#!/usr/bin/env bash
# Performance benchmark: analysis time vs lines of code.
# Generates synthetic PHP projects of increasing size, times the security suite, prints a table.
set -u
CODEQL="${CODEQL:-$REPO_ROOT/tools/codeql/codeql}"
REPO="${REPO:-$REPO_ROOT/codeql}"
WORK="$(mktemp -d)"
SUITE="$REPO/php/ql/src/codeql-suites/php-security.qls"

gen() { # $1 = number of functions
  local n=$1 f="$WORK/src$n"; mkdir -p "$f"
  { echo '<?php'
    for i in $(seq 1 "$n"); do
      echo "function f$i(\$p){ \$x = \$p; return system(\$x); }"
      echo "f$i(\$_GET['q$i']);"
    done
  } > "$f/a.php"
  echo "$f"
}

printf '%-10s %-10s %-10s\n' "functions" "LOC" "seconds"
for n in 50 200 800; do
  src=$(gen "$n")
  loc=$(wc -l < "$src/a.php")
  db="$WORK/db$n"
  "$CODEQL" database create "$db" --language=php --source-root="$src" --search-path="$REPO/php" >/dev/null 2>&1
  "$CODEQL" dataset measure --output "$REPO/php/ql/lib/php.dbscheme.stats" "$db/db-php" >/dev/null 2>&1
  t0=$(date +%s)
  "$CODEQL" database analyze "$db" "$SUITE" --format=csv --output="$db.csv" --search-path="$REPO/php" --additional-packs="$REPO" --threads=4 >/dev/null 2>&1
  t1=$(date +%s)
  printf '%-10s %-10s %-10s\n' "$n" "$loc" "$((t1-t0))"
done
rm -rf "$WORK"
