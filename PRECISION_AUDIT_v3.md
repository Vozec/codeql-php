# PHP CodeQL fork — precision & correctness audit, round 3

Third deep review (9 parallel static agents), run **against the current tree after v2 batches 10–17**. Same
goal: cover the existing frameworks **better** (loosen too-strict → recover FNs, tighten too-lax → kill FPs,
fix bugs), not more frameworks. Headline: the adversarial + FlowSources agents found **5 regressions in the
v2 batches themselves**, and the cross-cutting agent found that **T1-4 was never applied** (my v2 status table
wrongly implied it). `(N agents)` = independent corroboration.

Legend: **FN** too strict · **FP** too lax · **BUG** · **PERF** · **REGRESSION** = introduced by v2 batches 10–17.
Severity ★★★/★★/★. Every finding is static-verified with a concrete trigger.

---

## PRIORITY 0 — Regressions introduced by v2 batches 10–17 (fix first)

### R1. Batch 10 — the `&&`/`||` guard rejection is too aggressive → positive-then `&&` now FPs  `FP ★★★` (agent 1)
`FlowSources.qll` `guardUnderLogicalConnective` rejects **any** connective, but for a positive guard whose read
is in the THEN branch an `&&` conjunct is still guaranteed true there — clearing was correct.
```php
if (is_numeric($id) && $id < 100) { $db->query("… WHERE id = $id"); }   // safe, now REPORTED
```
The ubiquitous `ctype_digit($x) && $x < N` bound-check pattern now false-fires.
- **Fix:** polarity-aware — for the positive-then arm (`neg` even, read in body) reject only `||`/`or`/`xor`;
  keep the blanket rejection on the negated-else and early-exit arms (where `&&` breaks the guarantee).

### R2. Batch 16 — the StoredInjection write-side barrier is kind-blind → cross-kind stored injection dropped  `FN ★★` (agents 1, 5)
`StoredInjection.ql` `WriteConfig.isBarrier = Sanitizer` is kind-agnostic, so an SQL escaper on the write path
marks the key not-user-writable even for a **different-kind** read sink.
```php
update_option('cfg', $mysqli->real_escape_string($_POST['x']));   // SQL-escaped write
$v = get_option('cfg'); eval($v);                                 // code-injection read — now MISSED
```
- **Fix:** restrict the write barrier to **kind-agnostic** coercions (numeric — `isNumericValueBarrier` /
  numeric cast / intval) rather than the whole `Sanitizer` class; a numeric value is safe for every kind, an
  SQL-escaper is not. (Agent 5: the StoredXss feature needs its own `XssWriteConfig` — see T5-1.)

### R3. Batch 17 — `LaravelCollectionBarrier` uses `exprTypeName` (short name) → suppresses real builder sinks  `FN ★★` (agent 1)
The "recall-monotone" claim was wrong: `exprTypeName` resolves from **type annotations** for un-extracted
classes too, and returns the **short** name, so it matches any class named `Collection`, and it barriers
**every** argument (`getAnArgument()`).
```php
use App\Query\Collection;                     // a custom fluent DB wrapper, NOT Illuminate
function f(Collection $q) { $q->where($_GET['col'])->get(); }   // real column SQLi — now SUPPRESSED
```
- **Fix:** require the receiver's class to resolve via `exprClass` (a declared class) OR gate on a fully-
  qualified `Illuminate\…` name; and barrier only the sink argument index, not `getAnArgument()`.

### R4. Batch 11 — `isTrivialPassthrough` misses the constant-return-arm no-op (and indirect copies)  `FN ★★` (agents 1, 4)
"EVERY return a passthrough" counts a `return <constant>` guard-arm as "real work", so a main-path no-op keeps
its fake model; and `returnsUnmodifiedParam` still only matches a *direct* `return $param`.
```php
function esc_sql($x){ if ($x === '') return ''; return $x; }   // main path is a no-op → model KEPT → FN
function esc_sql($x){ $t = $x; return $t; }                    // indirect copy → still not detected → FN
```
- **Fix:** treat a `return <constant/empty>` arm as neutral (not "real work"), and follow SSA copies/casts
  (`$t=$param`, `(string)$x`, `$x ?? ''`) in `returnsUnmodifiedParam`.

### R5. Batch 15 — the query-builder step added generic setter names that fire on any object  `FP ★★` (agents 1, 3)
`set`/`select`/`values` are among the most common non-builder method names; the step taints the whole receiver.
```php
$config->set('title', $_GET['t']); echo $config->render();     // FP if the object reaches any sink
```
- **Fix:** gate the generic names (`set`/`setValue`/`values`/`select`/`addSelect`) on a resolvable builder
  receiver type, or require the chain to also contain a query-distinctive method; keep `where`/`andWhere`/
  `having`/`orderBy` (query-specific) unconstrained.

---

## TIER 1 — High-value pre-existing FN/FP

### T1a. `SymfonyBagSource` still lists the type-coercing bag accessors as sources  `FP ★★` (agents 2)
`FlowSources.qll` — the accessor set includes `getInt`/`getBoolean`/`getAlpha`/`getAlnum`/`getDigits`, which
coerce/whitelist to a non-injectable value. This re-introduces at the STRUCTURAL level exactly the FP that
model-level T1-6 removed (`symfony.model.yml` even comments "getInt is NOT a source"). **Fix:** drop those five
names; keep `get`/`all`/`getString`/`filter`.

### T1b. `ScalarParamBarrier` leaks into nested closures → shadowed attacker var over-barriered  `FN ★★` (agent 2)
A closure parameter shadowing the scalar param name is matched (`use.getParent+() = fn.getBody()` crosses
callable boundaries). `function h(int $id){ array_map(function($id){ query("…$id"); }, $_GET['ids']); }` →
the closure's `$id` is wrongly barriered → SQLi missed. **Fix:** require `use`'s nearest-enclosing callable to
be `fn` (reuse the `directlyInBody` shape).

### T1c. `RouteParamSource`/`AttributeRouteParamSource` have the same closure leak → spurious sources  `FP ★★` (agent 2)
Same `name + getParent+` scope: a same-named var in a nested closure in the handler body becomes a "route
parameter" source. **Fix:** bind the read to the callable that declares the parameter (nearest-enclosing).

### T1d. `receiverIsClass` ancestor arm makes `TypedSanitizerStrong` over-barrier generic sanitizer classes  `FN ★★` (agent 2)
The ancestor arm applies to `typedSanitizerModel`, whose classes are generic (`Connection`, `Db`, `Mysql`, and
especially processwire `Sanitizer` with `int`/`name`/`path`/`email`). Any app class named/deriving those has its
`->int()`/`->quote()` result treated as a full barrier → real SQLi/traversal hidden. P0-D only rescoped the
source/sink FP direction. **Fix:** gate the ancestor arm (and ideally the base arm) for sanitizers to
distinctive multi-token / namespaced class names.

### T1e. Engine: name-based call resolution is CROSS-KIND  `FP ★★` (agent 3)
`DataFlowPrivate.qll` `viableCallable` name-fallback (+ `getStringNamedCallee`, `lambdaCreation`,
`Closure::fromCallable`) match `getName()` with no function-vs-method discrimination, so a free-function call
resolves to an unrelated class's method and vice-versa. **Fix:** gate each fallback on matching kind (mirror
`resolvesToCallee`'s separate `FunctionDefinition`/`MethodDeclaration` arms).

### T1f. Engine: `getInvokeCallee` short-name resolution is uncapped  `FP/PERF ★★` (agent 3)
`DataFlowPrivate.qll` — sibling of the Batch-16-capped `getConstructCallee`, but `$x()` (`__invoke`) resolves by
short class name with no fan-out cap. **Fix:** add the same `count(ClassLike … name) <= 8` guard.

### T1g. Engine: a COLLECTING variadic parameter drops trailing args  `FN ★★` (agent 3)
`function q(...$parts){…}` called `q($a, $b)` maps only arg 0; `parameterMatch(ppos,apos){ppos=apos}` has no
variadic-collection arm, so `$b`'s taint is dropped. **Fix:** when the last formal is a `VariadicParameter` at
index k, map every argument position ≥ k to it.

### T1h. Engine: array-callable class-name arm + `getInvokeCallee` are the last uncapped short-name resolvers  `FP ★` (agent 3)
`TypeInference.qll` `arrayCallableMethod` `['C','m']` arm resolves by short class name with no cap (Batch-15 only
capped the *subtype* arm). **Fix:** `resolveClassReference` or the short-name count cap.

---

## TIER 2 — Model bugs

- **[FP ★★] laravel `integer`/`float`/`boolean` request getters modeled as SOURCES** (agent 6) — type-coerce to a
  scalar; contradicts the symfony `getInt` decision. `laravel.model.yml` — delete the three rows. (`date`/`enum`
  weaker offenders in the same family.)
- **[FN ★★] prestashop `Tools::purifyHTML` (HTMLPurifier) is a FULL sanitizer** (agent 6) — HTML allow-list leaves
  SQL metachars → escape-then-SQLi hidden. Move to `weakXssSanitizerModel` + `stepModel ["staticmethod","purifyHTML",0,-1]`.
- **[FN ★★] T1-4 was NEVER applied — bare `quote`/`escape`/`real_escape_string`/`quoteIdentifier` full sanitizers** (agents 6, 9)
  `php-builtins.model.yml` + `symfony.model.yml`. They (a) block XSS/command/path on any receiver (cross-context FN)
  and (b) **subsume and DEAD 15 `typedSanitizerModel` rows** (joomla/magento/prestashop/suitecrm/symfony/typo3).
  My v2 status table wrongly lumped this under "T1-1..9 done". *Correct fix is the per-kind sanitizer column
  (Tier 6-1); an interim delete-and-rely-on-typed recovers cross-context recall but risks SQLi FPs on unresolved
  global DB receivers — decide alongside Tier 6-1.*
- **[FN ★★] spip `sql_getfetsel` + `sql_countsel` under-cover injectable args** (agent 7) — my Batch-14 fix was
  incomplete: getfetsel missing `$groupby`(3)/`$having`(6); countsel missing `$from`(0)/`$groupby`(2)/`$having`(3).
- **[FN ★★] moodle `*_select` raw-WHERE family half-covered** (agent 7) — add `get_recordset_select`(1),
  `record_exists_select`(1), `get_field_select`(2), `get_fieldset_select`(2), `set_field_select`(3, a raw-WHERE UPDATE).
- **[BUG ★] php-builtins `array_walk -1,-1` step propagates taint into a BOOLEAN return** (agent 9) — same class as
  the removed `str_contains` step; `array_walk` returns `true` and mutates by-ref. Remove the row.
- **[FP ★] cacti `get_filter_request_var` coercing-getter source** (agent 7) — default `FILTER_VALIDATE_INT`; a new
  instance of the moodle/symfony coercing-getter residual. Drop or model kind-aware.
- **[FN ★] mediawiki `selectRow`/`selectField` miss `$tables`(0)/`$vars`(1)** (agent 7) — marginal (identifiers rarely tainted).

---

## TIER 3 — Access-control (agent 4 gave concrete fixes + recall-safety verdicts)

**SAFE to ship (corpus-safe by construction):**
- **T3-4 — `propertyReceiverClassName` uniqueness gate** `FN` — resolve `$this->prop`'s class only when a SINGLE
  class is assigned to it in the class body. WP `$this->db = $wpdb` is single-assignment → stays resolved →
  `prepare` stays a sanitizer → WP corpus green; only the unsound multi-assign case changes. `ModelExtensions.qll`.
- **T3-5 — `isSensitiveAction` category gate** `FP` — gate `missingAuthorization` to `["state-change","privilege"]`
  (exclude `sensitive-read`, which is IDOR-disclosure only), so IDOR-only rows don't double-fire missing-auth.
  Used only by `missingAuthorization` → can only drop findings → corpus-safe.
- **P0-J — `paramRebound` foreach/list/global/by-ref** `FP` — extend the rebind set; detecting MORE rebinds keeps
  MORE sanitizer models active (wp2shell-safe direction) → cannot create an un-annotated finding. `ModelExtensions.qll`.
- **`resolveHandler` uniqueness cap** `FP` — `AccessControl.qll:82` string-handler arm resolves `'save'` to every
  same-named function; gate `count(… name) = 1`.

**NEEDS-CORPUS (correct-by-construction but un-validatable statically — run 201/201 before shipping):**
- **T3-2 — `callIn` nearest-enclosing-callable** (closure leak; corpus-safe SUBSET = apply to the action side only).
- **T3-3 — `directCallee`/`reaches` uniqueness cap** (namespace-blind explosion; a high cap = pure PERF win, behavior-neutral).

**Also:** T3-6 (Idor/MissingAuth `@precision medium` excluded from `php-code-scanning.qls`) — add an `include: id:`
to the selectors file, do NOT raise precision (they match by bare name → real-world FPs). `argOf(-2)` staticmethod
dead-arm — document as method-only.

---

## TIER 4 — Query precision

- **[FP ★] OpenRedirect host-pin omits `:` → a pinned base WITH A PORT defeats the barrier** (agent 5) —
  `header("Location: https://intranet:8443/".$_GET['p'])` is reported. `OpenRedirect.ql` — add `:` to
  `[A-Za-z0-9._~%-]`. (Blind spot in the Batch-6 fix.)
- **[FP ★] TypeJuggling `sensitive()` substring match** (agent 5) — `.*(pass|token|…).*` fires on `$bypass`,
  `$compass`, `$subtokens`. Add word-ish boundaries. Also **negative-literal FP** (agent 1): `$attempts == -1`
  (unary-minus over `Integer 1`) still fires — accept a unary-minus over a non-zero numeric as benign.
- **[FN ★] WeakSecurityRandomness `isSecretName` omits `salt`/`key`/`code`/reset-activation family** (agent 5) —
  `$activation_key = md5(mt_rand())`, `$salt = mt_rand()` missed. Extend the regex; add `setrawcookie`/`session_id`.
- **[FN ★] StoredInjection sink kinds omit command injection & path traversal** (agent 8) — a stored option read
  into `system()`/`include` (second-order RCE/LFI) is missed. Add `"command injection"`,`"path traversal"`
  (+`"ldap injection"`,`"server-side request forgery"`) — the `Sanitizer` barrier is already correct for these.
- **[SEVERITY ★] StoredInjection `@security-severity 8.8` averages a 4-kind union incl. code/deser (base 9.8)** (agent 5) —
  stored RCE under-rated. Split or raise. Also **WeakRandom `@problem.severity warning`** is the lone non-`error`
  security query (agent 8) — cosmetic.

---

## TIER 5 — New capabilities & gaps

### T5-1. Stored reflected-XSS (CWE-79) — the T4-2 deliverable, with a concrete plan  `FN ★★` (agent 5)
Add a SEPARATE `php/ql/src/Security/StoredXss.ql`. Extract `StoredSource`/`storeWrite`/`storeRead`/`userWritableKey`
from `StoredInjection.ql` into a shared `StoredSources.qll` (one code-move). StoredXss needs its OWN
`XssWriteConfig` (`isBarrier = Sanitizer or XssSanitizer`) driving an `xssWritableKey` — do NOT add `XssSanitizer`
to the shared `WriteConfig` (escaped-HTML is still SQL/code-dangerous). Read config: `isSink = "reflected XSS"`,
`isBarrier = Sanitizer or XssSanitizer`. `@precision high @security-severity 6.1 @tags security external/cwe/cwe-079`
→ auto-joins all four suites, no manual registration. This catches BOTH escape-on-output and escape-on-write correctly.

### T5-2. XXE misses the entity-expanding-by-default parsers  `FN ★★` (agent 8)
`FlowSources.qll` XXE is flag-gated; uncovered: `xml_parse` (expat — expands entities BY DEFAULT, no flag),
`XMLReader::open/XML`, the property forms `DOMDocument::$substituteEntities/$resolveExternals = true`, and
`libxml_disable_entity_loader(false)`. Add expat/XMLReader as unconditional sinks; treat the property-set +
`libxml_disable_entity_loader(false)` as the unsafe-flag equivalent.

### T5-3. The audit subsystem runs in NO suite  `GAP ★★` (agent 8)
`SemgrepAudit.ql` is `@precision low @tags audit`; no suite selects `tags: audit`. So the whole
`auditPresence`/`auditArg`/... subsystem (~5 populated model blocks) never executes. Add a `php-audit.qls`
include-suite (mirror `php-access-control.qls`).

### T5-4. Mass-assignment / variable-injection has no query  `GAP ★` (agent 8)
`extract($_POST)` / `$model->fill($_POST)` / `(object)$_POST` are absent everywhere — a classic PHP class.
Cheapest as an `auditArg` rule once the audit suite (T5-3) runs.

### T5-5. Residuals: header/CRLF injection only covers `Location:` (`setcookie` value unmodelled); `accessPathReassignedBetween` misses foreach/list/by-ref (agents 1,2); `subscriptConstKey` leaks interpolated array keys (agent 2); the Yii `::$app->request` arm never checks the static property is `$app` (agent 2).

---

## TIER 6 — Structural investments (staged, recall-corpus-validatable)

### T6-1. Per-kind `vulnKind` column on sanitizers  (agent 8 — full design)
Add `kindSanitizerModel(kind,name,vulnKind)` + `typedKindSanitizerModel(class,name,vulnKind)` + a `KindSanitizer`
node class (mirror `DataSink`, route typed through `receiverIsClass`). Each query's barrier gains
`or n.(KindSanitizer).getKind() = "<its kind>"` (one line each). **No engine change** — barriers are per-query.
Migration: existing global rows stay live (day-one byte-identical). Then move SQL-only escapers (real_escape/pSQL/
addslashes/quote/escape/quoteIdentifier — resolving T1-4) → `kind("SQL injection")`; retire the 79 weak-XSS+step
rows → `kind("reflected XSS")` (**delete the paired step in the same commit** or re-open the escape-then-XSS FP).
Staging: Stage-0 no-op (201/201 bit-identical), Stage-1 SQL escapers (recall-monotone; new FPs surface as new
un-annotated corpus results for per-row triage), Stage-2 retire weak-XSS. This is the single biggest structural
cleanup — it resolves T1-4, T1d, the basename/realpath/escapeshellarg cross-context residuals, and the whole
weak-XSS+step apparatus.

### T6-2. Array field-sensitivity  (agent 8 — full design + the FN trap)
`TArrayKeyContent(k)` (constant keys) + `TArrayContent()` (dynamic fallback), key extraction via `constStringText`
(interpolation-rejecting — the P0-H lesson). Recall-critical: constant-key read must ALSO consult `TArrayContent()`;
dynamic-key read must consult EVERY `TArrayKeyContent(_)`. **The trap the earlier audits missed:** whole-array
consumers (`foreach`, `list()`, spread, `array_map`, casts, `"$a[x]"`) are modelled as WHOLE-NODE taint edges that
bypass `readStep` — every one must become an all-keys content read before constant stores are narrowed to specific
buckets, or flows drop. Staging: Stage-0 write-both (no-op, 201/201), Stage-1 convert consumers, Stage-2 narrow
constant stores (the only FN-risky step; the 201 corpus IS the FN harness — but the FP payoff is unmeasurable here).

---

## Corrections to the v2 audit doc
- **T1-4 is NOT done** (v2 status table wrongly implied it under "T1-1..9"). Bare `quote`/`escape`/`real_escape_string`/
  `quoteIdentifier` sanitizer rows remain (Tier 2 above); fix belongs with T6-1.
- **Batch 11 P0-A** is only partially fixed — the indirect-copy + constant-return-arm decoys remain (R4).
- **Batch 16 T4-3, Batch 17 T4-4** are regressions as landed (R2, R3).

## Appendix — verified clean (agents 8, 9)
All 25 extensible predicates are live (populated + consumed); every emitted `vulnKind` maps 1:1 to a query (no
case/spelling drift after the T1-1 drupal fix); no sanitizer↔weak-XSS or source↔sanitizer/sink same-name
collisions besides T1-4; all ~1500 rows have correct arity; sourceType is never filtered (no dead sources); all
weak-XSS rows across ~30 files have their paired carry step; Batch 12 (IDOR numeric-barrier subtraction) and the
Batch-13 sprintf-pad regex are sound.

*Methodology: 9 static agents (adversarial review of v2; FlowSources; dataflow engine; AccessControl+IDOR+
ModelExtensions; query files + StoredXss plan; flagship+builtins models; remaining CMS models; systemic+structural;
cross-cutting+dead-code), current tree, no DB builds. Cross-corroboration noted per finding.*

---

## IMPLEMENTATION STATUS (v3 batches 18–24 — corpus held 201/201, 0 un-annotated throughout, each probe-verified)

**Fixed & verified:**

| Item | Batch | Fix |
|------|-------|-----|
| R1 | 18 | polarity-aware guard connective rejection (positive-then rejects `||`, negated arms reject `&&`) |
| R3 | 18 | LaravelCollectionBarrier restricted to `collect(...)`-rooted receivers + column arg |
| R4 | 19 | passthrough gate follows copies/casts + treats a constant-return arm as neutral |
| R2 | 19 | StoredInjection write barrier restricted to kind-agnostic numeric coercions |
| R5 | 20 | generic query-builder setters (`set`/`select`/`values`) gated on a builder-chain receiver |
| T1a | 21 | dropped the coercing bag accessors (getInt/getBoolean/…) from SymfonyBagSource |
| T1b/T1c | 21 | ScalarParamBarrier / RouteParamSource no longer leak into nested closures (`notInNestedCallable`) |
| M1..M4 | 22 | laravel coercing sources removed; prestashop purifyHTML→weak-XSS; spip getfetsel/countsel + moodle *_select gaps; array_walk step removed |
| Q1..Q3 | 23 | OpenRedirect port `:`; TypeJuggling name word-boundary + negative literal; WeakRandom salt/reset names + setrawcookie/session_id |
| P0-J | 24 | paramRebound foreach/list/global (recall-safe) |
| T3-5 | 24 | isSensitiveAction gated to state-change/privilege (missing-auth double-fire) |
| T1f/T1h | 25 | getInvokeCallee + array-callable class-name fan-out caps |
| T3-4 | 26 | propertyReceiverClassName uniqueness gate (multi-assign no longer a definite sanitizer receiver) |
| resolveHandler | 26 | string-handler entrypoint uniqueness cap |
| T5-2 | 27 | XXE `xml_parse` (expat) unconditional sink |
| stored cmd/path | 27 | StoredInjection second-order command/path/SSRF/LDAP sinks |
| T5-1 | 28 | NEW php/stored-xss query (CWE-79) + shared StoredSources.qll |
| T5-3 | 29 | php-audit.qls opt-in suite (un-blocks the audit subsystem) |

| Tier 6-1 | 30-32 | **per-kind `vulnKind` sanitizer column** — Stage 0 (plumbing, verified no-op) + Stage 1 (SQL escapers) + Stage 2 (shell→command, basename/realpath→path/file). Resolves T1-4 and the whole escaper-context-blindness FN class (SQL/command/path). |
| T1g | 33 | collecting variadic param `...$parts` receives all trailing arguments |
| T1d | 34 | TypedSanitizerStrong drops the ancestor arm (no subclass over-barriering) |

| Part B | 35 | NEW php/variable-injection query (mass assignment / `extract($_POST)`, CWE-621) |
| T3-2 | 36 | callIn nearest-enclosing-callable (guard-in-closure no longer suppresses) |
| T1e | 36 | reverted — root cause found (cast not instanceof), but even the correct cast regresses the corpus; needs per-flow analysis |
| Part D | 37 | array field-sensitivity — execution-ready plan `ARRAY_FIELD_SENSITIVITY.md` (de-risked consumer checklist); not implemented (FN-risky Stage 2 + FP-unmeasurable here) |

**Still open:** the per-kind mechanism now EXISTS and Stage 1 (SQL) is done — extending it to shell escapers
(`escapeshellarg`→command) and path escapers (`basename`/`realpath`→path/file-read/file-inclusion) is a
straightforward follow-on (move the rows + paired steps, same pattern). Also: array field-sensitivity
(Tier 6-2), a careful redo of T1e (cross-kind resolution — the naive gate regressed the corpus), T1d
(ancestor-arm typed sanitizer), T1g (collecting variadic), T3-2/T3-3 (needs-corpus AC), mass-assignment query.

**T1e (cross-kind name resolution) deferred** — a naive function-only/method-only gate on the viableCallable
name-fallback regressed the corpus (200/201); the DataFlowCallable↔AST kind relation needs a more careful
predicate than `instanceof Php::MethodDeclaration`.

**Remaining (not yet applied — all documented above with fixes):**
- **Engine T1e/T1f/T1g/T1h** — cross-kind name resolution split; `getInvokeCallee` cap; collecting-variadic param; array-callable class-name cap. (Contained, corpus-validatable.)
- **T1d** — `receiverIsClass` ancestor arm over-barriers generic typed sanitizers (needs distinctive-name gating for `TypedSanitizerStrong`).
- **Access-control**: T3-4 (`propertyReceiverClassName` uniqueness gate — SAFE per agent 4), `resolveHandler` uniqueness cap (SAFE); T3-2/T3-3 (NEEDS-CORPUS); T3-6 (suite include).
- **New capabilities**: T5-1 StoredXss (CWE-79), T5-2 XXE `xml_parse`/XMLReader/property-forms, T5-3 audit `php-audit.qls`, T4 StoredInjection command/path sinks + severity split.
- **Tier-5 residuals**: header/CRLF `setcookie`, `accessPathReassignedBetween` foreach/list, `subscriptConstKey` interpolation, Yii `::$app` property check.
- **Structural (Tier 6)**: per-kind `vulnKind` sanitizer column (resolves T1-4 + the escaper churn) and array field-sensitivity — both with staged, recall-corpus-validatable designs.
