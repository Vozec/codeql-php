# Precision roadmap — PHP SQL-injection false positives

State after the 2026-08-09 precision push. **phpBB SQLi: 847 → ~102** distinct sink sites,
**corpus 201/201 throughout**, every change **pure PHP source only** (no external schema/config),
each validated on the double oracle.

## The double oracle (run BOTH on every change)

- **Recall** — `bash cve/run.sh` — the 201-CVE corpus. MUST stay `201/201, 0 un-annotated`.
  A dropped count = a real vulnerability now hidden (FN). This is non-negotiable.
- **Precision** — `bash /home/vozec/Bureau/dev/_ql_work/benchmark/eval.sh` — 198 manually-labeled
  phpBB SQLi findings (all FP, categorized). Reports FP-eliminated, **TP-lost (recall regression)**,
  and new unlabeled findings. Oracle files in `/home/vozec/Bureau/dev/_ql_work/benchmark/`
  (`labels.json`, `BENCHMARK.md`, `eval.sh`).

**Rule:** a big precision drop that ALSO drops the corpus is an FN-hiding regression, not a win.
Proven the hard way: a `*_id` key-name barrier scored 115/198 FP but hid 4 real unauth SQLi
(OpenCart CVE-2024-21514/CVE-2025-0214, AbanteCart CVE-2024-50801/50802). The benchmark exists to
make that visible.

## Remaining 102 phpBB SQLi FPs, by category

### 1. int-convention — 49 (biggest) — needs PARAMETER type inference
Bare variables / function params that are integers by convention: `WHERE forum_id = $forum_id`
where `$forum_id` is a function param (`get_forum_info($forum_id)`). Already handled: literal
`variable('x',0)` defaults, `(int)`/arithmetic/numeric-builtins (TypeFlow), and DB-int-column reads
(`$row['forum_id']`, `$user->data['user_id']` — provenance-gated in `producesNumericValue`).

Options for the param residual (each **oracle-gated**, back off if corpus < 201):
- [ ] **Interprocedural (SOUND, preferred):** a param is numeric if EVERY argument at EVERY call site
      is `producesNumericValue`. Now that DB-int-columns + literals + casts are numeric, many phpBB ID
      params are all-numeric-caller. Expensive but no FN risk.
- [ ] **Param-name heuristic (UNSOUND, risky):** `$*_id`/`$*_time` param → numeric. Let the oracle
      judge — likely hides some real `$something_id` string SQLi in other frameworks. Only if the
      interproc version is too costly, and only if corpus stays 201.

### 2. escaped — 38 — needs the CONTENT-FLOW rebuild (#3)
Values escaped per-element then assembled: `implode(' AND ', $where_sql)` where each `$where_sql[]`
is `sql_escape`'d, or `sql_build_query` results. The engine's array taint is node-level (a whole-array
consumer sees any element's taint), so per-element escaping is not tracked.

The rebuild (diagnosed 2026-08-09, spec in memory `cms-audit-campaign.md`):
- [ ] Convert node-level CONTAINER SOURCES to CONTENT sources: `$_GET` must STORE its taint into
      `TArrayContent` (source objects into `TFieldContent(*)`), so `$_GET['x']` / `$o->f` read it
      natively via `readStep` — NOT via the `structuralPropagator` base→member step B.
      (`defaultImplicitTaintRead` does NOT bridge node→content — measured, it collapses everything.)
- [ ] Route whole-array consumers (`implode`/`foreach`/`array_map`/`array_merge`/…) through content reads.
- [ ] Add `clearsContent` for sanitized element writes (`$where[]=sql_escape($v)` clears that cell).
- [ ] THEN delete the node-level amplifiers A (whole-container re-taint) + B (structuralPropagator
      MemberAccess/subscript arms). Field-sensitivity becomes by-construction; most existing barriers
      (`ConstantSiblingKeyBarrier`, `$this`-B exclusion) become unnecessary.
- HIGH FN risk — measure corpus at EVERY step. This is the principled fix that removes the root all the
  precision barriers patch.

### 3. tail — 15
- [ ] schema-tool 7 — remaining DB extractor/migration table names not covered by the
      `array_intersect(sql_list_tables(),…)` whitelist. Trace their other whitelists / provenance.
- [ ] guard-validated 4 — `in_array($x, permission_dropdown)` whitelists + `preg_match` numeric CAPTURE
      GROUPS (`$m[1]` of `([0-9]+)` is numeric — needs regex-capture char-class inference).
- [ ] internal-constant 3 — interpolated `$table`/`$field` identifiers that are compile-time constants
      (def-use / constant-propagation).
- [ ] sink-misattribution 1 — `router.php:349` `Route::setCondition` (Symfony routing) hit by the
      Pimcore bare-method SQL sink `symfony.model.yml:83 ["method","setCondition",…]`. Same cross-
      framework bare-sink collision class as e107 `["method","delete",…]`. Scoping to the Pimcore
      Listing class would fix it but risks Pimcore recall (untyped receiver) — decide.

## Cross-framework bare-method sink pollution (general hygiene)
Bare-method sink rows from one CMS fire on every other framework's same-named method:
`setCondition` (Pimcore → Symfony routing), `delete`/`select`/`count` (e107 → phpBB `$log->delete`).
- [ ] A receiver-type-compatibility gate on bare-method sinks, OR scope them to their framework classes
      (loses recall when the receiver is untyped — the e107/Pimcore dilemma). Needs a call decision.

## Known caveats shipped
- `DriverQueryParamBarrier` barriers by method NAME (phpBB `sql_query` family). A non-phpBB app with an
  UNMODELED method literally named `sql_query` used as its only wrapper could FN. Accepted (distinctive
  names, corpus clean). Tighten by requiring the enclosing method to be a modeled sink if needed.
- `dbFetchDerivedBase` is flow-insensitive (a var re-assigned from request after a fetch could
  over-barrier). Corpus-clean; refine with SSA if a benchmark shows an FN.

## Extend the benchmark (unblocks measuring other frameworks)
- [ ] Triage real findings for drupal / magento / other CMS the same way (7 parallel agents reading
      source, TP/FP + category) → per-framework `labels.json`. Currently only phpBB SQLi is labeled;
      other frameworks / other query kinds (XSS, path) fly blind on real-framework recall.
