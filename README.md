<h1 align="center">CodeQL for PHP</h1>

<p align="center">
  <b>A complete PHP language pack for <a href="https://github.com/github/codeql">CodeQL</a></b><br>
  Extractor · AST · CFG · SSA · interprocedural taint · framework models · security queries
</p>

<p align="center">
  <img alt="tests" src="https://img.shields.io/badge/tests-43%20green-2ea44f">
  <img alt="queries" src="https://img.shields.io/badge/security%20queries-13-blue">
  <img alt="frameworks" src="https://img.shields.io/badge/frameworks-Laravel%20·%20Symfony%20·%20WordPress%20·%20PrestaShop%20·%20TYPO3-8957e5">
  <img alt="status" src="https://img.shields.io/badge/DVWA-50%20taint%20findings-orange">
</p>

---

## Why

PHP powers a huge share of the web, yet has **no first-party CodeQL support**. This fork adds a
`php/` language pack that plugs into the standard CodeQL toolchain and reuses the language-agnostic
`shared/` engine (dataflow, SSA, control-flow, tree-sitter extractor) — so PHP gets the *same* global
taint tracking, path queries and Models-as-Data extensibility as Java, Ruby or Python.

The guiding principle is **no blind spots**: no execution path or data-flow branch is silently
dropped because a syntactic case wasn't modelled. Where the static model is incomplete, the analysis
**over-approximates** (a possible false positive) rather than **cutting a path** (a silent false
negative).

## What's inside

```
php/
├── extractor/        Rust extractor (tree-sitter-php → TRAP), ~250 LOC over shared/tree-sitter-extractor
├── ql/lib/           The language library:
│   ├── ast/          AST wrappers (classes, calls, expressions, statements, namespaces)
│   ├── controlflow/  CFG with real branching for if / if-else (SSA φ at joins)
│   ├── dataflow/     SSA, local flow, type inference, interprocedural taint steps
│   ├── security/     Sources, sinks, sanitizers, framework abstractions
│   └── ext/          Models-as-Data: Laravel · Symfony · WordPress · PrestaShop · TYPO3 · crypto
├── ql/src/           13 security queries + coverage/routing utilities
└── ql/test/          43 tests (query-tests + library-tests)
```

## Highlights

- **Type-based call resolution.** A dedicated type-inference layer (`exprClass`, `viableCallable`)
  resolves method targets by the receiver's *type* (`new C()`, `$this`, typed params/properties,
  SSA, declared returns, fluent `return $this`, `clone`, dynamic `new $c()`), with a name-based
  fallback for recall. `$safe->run()` is no longer a false positive.
- **Real control-flow branching.** `if` / `if-else` produce genuine SSA **φ** at the join, and taint
  crosses the join via phi-input flow (`definitionReachingValue`) — not a linearised approximation.
- **All the PHP that trips other tools.** Magic methods (`__get`/`__call`/`__invoke`/`__toString`/…),
  named arguments, references (`&`), generators, closures/arrow captures, `parse_str`, exceptions,
  higher-order callbacks, `$GLOBALS`, cross-file globals, dynamic instantiation, type juggling (CWE-697).
- **Frameworks as data.** Laravel, Symfony, WordPress, PrestaShop and TYPO3 sources/sinks/steps ship
  as `ext/*.model.yml` — community-extensible with **zero engine changes**.

## Quick start

> Requires the [CodeQL CLI](https://github.com/github/codeql-cli-binaries). See **[`DEV.md`](DEV.md)**
> for the full, reproducible setup.

```bash
# 1. Build the extractor + pack
php/build.sh

# 2. Create a database from a PHP project
codeql database create mydb --language=php --source-root=/path/to/app --search-path=php

# 3. Run the security suite
codeql database analyze mydb php/ql/src/codeql-suites/php-security.qls \
    --format=csv --output=results.csv --search-path=php --additional-packs=.

# 4. Run the tests
codeql test run php/ql/test --search-path=php --additional-packs=.
```

## Validation

Benchmarked on **DVWA** (Damn Vulnerable Web Application): **50 taint findings** across SQLi, command
injection, XSS, path traversal, etc., **17 type-juggling** findings, and only the paths in
`impossible.php` (prepared-statement guarded) are surfaced — a documented, bounded over-approximation.
The `php/ql/test` suite has **43 green tests** covering each engine feature.

## Status & roadmap

This is active research toward a production-grade PHP analyzer. The engine foundations (type
inference, dispatch, taint steps, framework models, and `if`/`if-else` control-flow branching) are in
place and tested. Remaining work — loops, `switch`/`match`, short-circuit operators, sanitizer
guards, engine-level post-update, and a labelled precision/recall corpus — is tracked, per pipeline
stage and test-first, in:

- **[`PROJECT_STATUS.md`](PROJECT_STATUS.md)** — single-page handoff: done / remaining / how to resume
- **[`STRUCTURAL_ROADMAP.md`](STRUCTURAL_ROADMAP.md)** — detailed roadmap by CodeQL pipeline stage
- **[`IMPROVEMENTS.md`](IMPROVEMENTS.md)** — audit-driven improvement plan (~30 items)
- **[`THREAT_MODEL.md`](THREAT_MODEL.md)** — soundness scope and assumed over-approximations

## License

Built on [`github/codeql`](https://github.com/github/codeql), licensed under the
[MIT License](LICENSE). The added `php/` pack follows the same license.

<sub>This repository is a research fork and is not affiliated with or endorsed by GitHub.</sub>
