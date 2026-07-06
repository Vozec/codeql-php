# Adapting the analyzer to a framework / CMS

Adapting to WordPress, Laravel, a custom CMS, … is **pure data**: rows in
`php/ql/lib/ext/<framework>.model.yml`. No QL, no engine recompilation. See
[framework-coverage.md](framework-coverage.md) for what is already covered.

## Mental model

```
source ──▶ [step] ──▶ [step] ──▶ sink
             │
     sanitizer / guard cuts the flow
```

You describe, as data, these roles for the framework's APIs. The engine does the rest (interprocedural
tracking, arrays, fields, closures, …).

## The rule vocabulary

| Predicate | Role | Columns |
|---|---|---|
| `sourceModel` | user input | `subjectKind, name, sourceType` |
| `typedSourceModel` | source only on class `C` | `className, method, sourceType` |
| `sinkModel` | dangerous argument | `subjectKind, name, argIndex, vulnKind` |
| `typedSinkModel` | sink only on class `C` | `className, method, argIndex, vulnKind` |
| **`stepModel`** | **intermediate rule** (taint passes through) | `subjectKind, name, fromArg, toArg` |
| `sanitizerModel` | neutralises taint | `subjectKind, name` |
| `typedSanitizerModel` | sanitizer only on class `C` | `className, method` |
| `sanitizerGuardModel` | `if (g($x))` validator | `name` |
| `callbackModel` | higher-order callback | `name, callbackArg, dataArg` |
| `outRefModel` | writes taint into a by-ref arg | `name, fromArg, toRefArg` |
| `routeHandlerModel` | router → handler closure params are sources | `subjectKind, name, handlerArgIndex` |

- `subjectKind` ∈ `function` / `method` / `staticmethod`.
- `argIndex`/`fromArg`: `-1` = any argument. `toArg`: `-1` = return value.
- `vulnKind` (exact strings): `SQL injection`, `reflected XSS`, `server-side request forgery`,
  `path traversal`, `open redirect`, `code injection`, `command injection`, `unsafe deserialization`.
- `className` is the **unqualified** short name; matched against the receiver's inferred type (exact,
  no subtype walk — list interface + concrete names when in doubt).

## Precision rule of thumb

Use the **typed** predicates whenever a method name is generic (`get`, `query`, `request`, `read`,
`quote`). A bare `["method","get",…]` row would fire on every `->get()` in the codebase; a
`["SomeClass","get",…]` typed row fires only on the right receiver. Never mark a kind-specific sanitizer
(e.g. an XSS-only escaper) as a general `sanitizerModel` — it would mask SQLi/traversal.

## "Intermediate rules" = `stepModel`

A `stepModel` says "taint enters at arg X and leaves at arg Y". It is the glue between a source and a
sink through a helper. Example — a plugin rebuilding a URL:

```php
$url = add_query_arg('q', $_GET['term'], $base);   // taint crosses add_query_arg
echo $url;                                           // XSS
```

Without a rule the engine stops at `add_query_arg`. One row fixes it:

```yaml
  - addsTo: { pack: codeql/php-all, extensible: stepModel }
    data:
      - ["function", "add_query_arg", -1, -1]    # any arg → return value
```

## Running an audit on a real project

```bash
export PATH="$PWD/.tooling/codeql:$PATH"
# build the extractor pack once (bench/run.sh shows the exact copy steps into $EXT)
codeql database create /tmp/plugin-db --language=php \
  --source-root=/path/to/plugin --search-path=/tmp/php-ext --threads=4

codeql database analyze /tmp/plugin-db \
  php/ql/src/codeql-suites/php-security-extended.qls \
  php/ql/src/Security/SemgrepAudit.ql \
  --format=sarif-latest --output=results.sarif \
  --search-path="$PWD/php" --additional-packs="$PWD"
```

Open `results.sarif` in VS Code (SARIF Viewer) for source→sink paths.

## Validate your additions

Run the benchmark after editing a model — it guards recall and the false-positive count:

```bash
bash bench/run.sh          # RECALL x/232 | FP-on-ok y/176 ; diffs against bench/baseline.txt
```

If FP rises, a row is too broad — make it a `typed*` variant or drop it.
