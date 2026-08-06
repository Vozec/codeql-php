# PHP CodeQL fork — precision & correctness audit, round 2

Second deep review (9 parallel static-analysis agents over the queries, taint libs, dataflow engine,
AccessControl, and all 37 model files), run **against the current tree after the 9 precision batches**
(commits Batch1 `2a5110241ac` → Batch9 `af3439ed2e5`). Goal unchanged: cover the existing frameworks
**better** — loosen too-strict logic (false negatives), tighten too-lax/imprecise logic (false positives),
kill bugs. Not more frameworks.

Legend: **FN** misses real vulns (too strict) · **FP** fires on safe code (too lax) · **BUG** · **PERF** ·
**REGRESSION** = introduced by the last 9 batches. Severity ★★★/★★/★. `(N agents)` = independent
corroboration (higher = more confident). Every finding is static-verified with a concrete triggering example;
none re-report an already-fixed or documented-deferred item from `PRECISION_AUDIT.md`.

---

## PRIORITY 0 — Regressions from the last 9 batches (fix first)

These are defects the recent work *introduced*. Highest priority because they degrade code that was
previously correct or that the batch was meant to fix.

### P0-A. `isTrivialPassthrough` is wrong in BOTH directions — re-opens the wp2shell FP *and* lets decoys through  `FP+FN ★★★` (agents 3, 8)
`ModelExtensions.qll:283-322`. The Batch-5 gate fires when *any single* `return $param` exists, with no
"is this the only behavior" check and matching only a *direct* param return.
- **FP** (agent 3): a real framework sanitizer with an early-out guard — `function esc_sql($v){ if(!is_scalar($v)) return $v; … return $escaped; }` — satisfies the gate → its model is switched OFF while scanning the CMS that defines it → every escaped query false-fires (the exact wp2shell footgun Tier-1-C closed).
- **FN** (agent 8): an *indirect* no-op decoy escapes the gate — `function esc_sql($x){ $t=$x; return $t; }` / `return $x ?? '';` / `return (string)$x;` → model kept → real flow hidden.
- **Fix:** classify as passthrough iff the returned SSA value is *transitively* an unmodified parameter (follow `$t=$param`/cast/concat-empty copies), AND *every* return in the body is such a passthrough, AND restrict returns/rebinds to those whose nearest-enclosing `Callable` is this function (the `getParent*` at :302 currently leaks into nested closures). Also match by fully-qualified name, not last segment (`:319`, agent 3).

### P0-B. Guard barrier ignores `&&`/`||` siblings — the parity model is unsound  `FN ★★★` (agents 1, 2, 8 — triple-confirmed)
`FlowSources.qll:85-94,139-160`. `guardNegationCount` counts only `!` ancestors; the doc-comment's claim
that "`&&`/`||` structure is folded into the `!`-parity count" is false. The new else-branch and
early-exit arms then clear reads that aren't actually validated on the taken path:
```php
if (!ctype_digit($id) && $strict) return;  $db->query("… $id");     // $strict=false → SQLi, but CLEARED
if (is_numeric($id) || $isAdmin) { runQuery($id); }                 // $isAdmin → un-numeric $id, CLEARED
```
- **Fix:** clear only when the guard is the *sole* controlling term — reject when a `BinaryExpression` with operator `&&`/`||`/`and`/`or`/`xor` sits between the guard and `ifs.getCondition()`.

### P0-C. Access-control IDOR engine doesn't exclude the new numeric barriers — canonical typed-id IDOR is a false negative  `FN ★★★` (agent 9)
`AccessControlTaint.qll:24-58`. The IDOR taint engine subtracts only 3 hardcoded numeric barriers
(`isNumericCoercion` + `isNumericGuardedRead`), but the barriers added in Batches 5–6 and the scalar-param
commit are NOT excluded, so they kill IDOR flows:
- `ScalarParamBarrier` (`FlowSources.qll:1208`): for `Route::get('/u/{id}', fn(int $id) => Model::destroy($id))` and Symfony `#[Route] show(int $id){ …->remove($id); }` the source node **is** the barrier node → flow can't even start. Typed-int controller params are THE canonical IDOR entry.
- `SettypeBarrier`, `FilterVarNumericBarrier` (`filter_var($_GET['id'],FILTER_VALIDATE_INT)`), and `NumericCastSanitizer`'s `(bool)`/`(real)` casts — all block IDOR.
- **Fix:** in the AC engine exclude *all* numeric-coercion `Sanitizer`s (add ScalarParamBarrier/SettypeBarrier/FilterVarNumericBarrier + the real/bool casts) and add the matching coercion steps. **Recall-safe** — affects only `Idor.ql`, monotone-additive to IDOR recall, cannot create injection FPs.

### P0-D. `receiverIsClass` ancestor arm creates a cross-framework false-source flood  `FP ★★★` (agent 1)
`FlowSources.qll:577-596` + `ext/concrete.model.yml:9-11`. The subtype/ancestor arm (commit `21a95b1`) makes
`typedSourceModel ["AbstractController","get"/"post"/"request","symfony-request"]` (Concrete5) fire on
*every Symfony controller subclass*: Symfony's `AbstractController::get('twig')` returns a **service**, not
user input, yet `$this->get(...)` in all controllers becomes a `symfony-request` source → pollutes SQLi/XSS/
SSRF/etc. Same widening hits generic single-token typed-**sink** class names (`Client::get`→SSRF, `File::write`,
`Db`, `Connection`) at `:878-906`.
- **Fix:** rescope Concrete5's rows off the `AbstractController` name; for the ancestor arm, gate on distinctive (multi-token / framework-unique) class names and drop it for generic single-token names.

### P0-E. Batch-9 fanout cap is a hard cliff — >8 implementors drops ALL dispatch  `FN ★★` (agent 8)
`TypeInference.qll:238-255`. `count(...) <= 8` is constant over the `exists`; at 9 implementors the whole
disjunct fails → `getTypedCallee()` empty → name-fallback also fails (global count ≥ subtype count > 8) → zero
viable callees, taint enters no body. A 9-implementor `interface Handler{ handle($r); }` with a SQL sink in one
impl → **FN across all**. The count also folds in abstract/interface stubs, tripping below 8 concrete targets.
- **Fix:** don't null the relation — keep up to N nearest-in-hierarchy targets, or gate per-`result` so precise sub-hierarchies still resolve.

### P0-F. Barriers clear *reassigned* variables (name-based, no SSA kill) — Batch 3 & Batch 8  `FN ★★` (agents 2, 8)
`FlowSources.qll:119-126,153-157` (guard early-exit) and `:1230-1251` (`SettypeBarrier`). Both match by
variable NAME via `sameAccessPath`/block-order with no reassignment kill:
```php
if (!ctype_digit($id)) die();  $id = $_POST['id'];  $db->query("…$id");   // re-taint ignored → FN
settype($id,'int');            $id = $_GET['id'];    $db->query("…$id");   // re-taint ignored → FN
```
- **Fix (shared root cause):** intersect with SSA — only clear reads sharing the guarded/coerced value's SSA def, or bail if any assignment to the access path lies between the barrier statement and the use. One SSA-based fix to `sameAccessPath`/`readAfterInSameBlock` closes both.

### P0-G. TypeJuggling fix was incomplete — non-string literals still FP  `FP ★★` (agent 1)
`TypeJuggling.ql:28-36`. Batch-7's `benignConstStr` only whitelists `String`/`EncapsedString`, so the doc's own
example `$passes == 3` (Integer RHS), `$attempts == 5`, `$token == false`, `$secret == null` still fire at
`@precision high`.
- **Fix:** also treat integer/float/bool/null literals as benign, keeping only the juggle-exploitable forms (`0`, `'0'`, `''`, `false`, `null`, magic-hash `0e\d+`) reportable.

### P0-H. `constantStringValue` leaks partial text from interpolated strings → source under-classification  `FN ★★` (agent 2)
`FlowSources.qll:236-240`. It returns each `StringContent` child, so on `"int$suffix"` it yields `"int"`,
silently dropping the interpolation. This makes a *dynamic* Dolibarr GETPOST type look SQL-safe
(`GETPOST('id',"int$suffix")` → treated as `int` → not a source → SQLi FN), and mis-classifies `getenv("PATH_$x")`.
- **Fix:** use the interpolation-rejecting `constStringText` (already at `:1101`) in the key/type-classification sites (`GetpostSource`, `GetenvSource`, `GetpostHtmlXssBarrier`, `PhpInputSource`), keeping `constantStringValue` only where a partial literal is harmless.

### P0-I. Batch-5 `SprintfNumericBarrier` defeated by a custom pad char  `FN ★` (agent 8)
`FlowSources.qll:1148-1160`. `sprintf("name=%'@10s id=%d", $name, $id)` — the `%'@` custom pad stops the flag
run before `[sc]`, so the `%s` string conversion is undetected and the whole call is marked a full sanitizer.
- **Fix:** consume the `%'<c>` pad token before scanning for `[sc]`, or reject the format if any `%` isn't fully parsed as a numeric spec.

### P0-J. Batch-5 `paramRebound` misses by-ref/list/foreach/global rebinds  `FP ★` (agent 8)
`ModelExtensions.qll:283-308`. Only `=`/`.=`/`=&` LHS are seen, so `function my_clean($x){ ref_filter($x); return $x; }`
(by-ref escape) is misread as passthrough → its model dropped → escaped output false-fires. Also misses
`list($x,…)=`, `foreach(… as $x)`, `global $x`.
- **Fix:** count a param passed to a by-ref parameter (and list/foreach/global targets) as rebound.

---

## TIER 1 — Model & query bugs (high value, mostly clean fixes)

### T1-1. Drupal `"reflected xss"` is lowercase → 3 DEAD rows  `BUG/FN ★★★` (agent 5)
`ext/drupal.model.yml:47-49`. Queries match `"reflected XSS"` (capital); no query matches lowercase. So
`Markup::create` / `FormattableMarkup::__construct` / `SafeMarkup::set` markup-XSS is missed for all Drupal 8/9/10.
- **Fix:** change the three rows' kind to `"reflected XSS"`.

### T1-2. Laravel `e()` (Blade escaper = htmlspecialchars) is a FULL sanitizer → escape-then-SQLi FN  `FN ★★★` (agents 5, 7)
`ext/laravel.model.yml:205`. The most common Laravel escaper blocks *all* kinds; `DB::raw("… ".e($_GET['x']))`
is silently safe. Missed in the Batch-2/4 escaper sweep.
- **Fix:** move `["function","e"]` to `weakXssSanitizerModel` + `stepModel ["function","e",0,-1]`.

### T1-3. WordPress escaper split only half-applied  `FN ★★` (agents 5, 7)
`ext/wordpress.model.yml:39-48`. Still FULL sanitizers (leave SQL quotes): `wp_kses`/`wp_kses_post`/
`wp_kses_data` (HTML allow-list), `esc_js` (`'`→`\'`, wrong for SQL), `esc_url`/`esc_url_raw`, `sanitize_email`
(keeps `'`/`/`). Each hides escape-then-SQLi.
- **Fix:** move `wp_kses*`/`esc_js` (and, more conservatively, `esc_url*`/`sanitize_email`) to `weakXssSanitizerModel` + paired steps. (`esc_html`/`esc_attr`/`sanitize_text_field` are already correct.)

### T1-4. php-builtins bare `quote`/`escape`/`real_escape_string` override the typed SQL escapers *and* are cross-context  `FN ★★` (agent 7)
`ext/php-builtins.model.yml:172-174`. Bare `["method","escape"/"quote"]` full-sanitizer rows (a) block XSS/
command/path (`echo $mysqli->real_escape_string($_GET['x'])` leaves `<>` → XSS FN) and (b) globally shadow the
careful `typedSanitizerModel` rows in joomla/symfony/prestashop/drupal (whose whole purpose is defeated).
- **Fix:** drop the bare `escape`/`quote` sanitizer rows (rely on the typed ones), or move to weak-XSS+step.

### T1-5. Symfony `["staticmethod","escape"]` full sanitizer overrides Drupal's `Html::escape` weak-XSS split  `FN ★★` (agents 5, 7)
`ext/symfony.model.yml:95`. A bare full-sanitizer wins globally over Drupal's weak-XSS `escape` (`:76/87`) → the
escape-then-SQLi the Drupal rows catch is re-hidden.
- **Fix:** delete the row (Drupal's weak-XSS `escape` already covers all `escape()` calls) or mirror it as weak-XSS+step.

### T1-6. Symfony `InputBag::getInt` modeled as a SOURCE (it type-coerces to int)  `FP ★★` (agents 5, 7)
`ext/symfony.model.yml:22`. Contradicts modern-frameworks (which deleted these) and joomla/xoops (which model
`getInt` as a *sanitizer*). An int can't carry a payload.
- **Fix:** delete the row; keep `getString` (`:21`).

### T1-7. SPIP `sql_fetsel`/`sql_allfetsel`/`sql_getfetsel` under-cover injectable args  `FN ★★` (agent 6)
`ext/spip.model.yml:41-46`. These share `sql_select`'s signature but are modeled at only args 2,4 (vs sql_select's
0,1,2,3,4,6). Tainted `$select`/`$from`/`$groupby`/`$having` → SQLi that flows nowhere.
- **Fix:** add the missing arg rows (0,1,3,6 for fetsel/allfetsel; 1,4 for getfetsel) to mirror `sql_select`.

### T1-8. Concrete5 bare `["view","unauthenticated"]` entrypoint floods access-control  `FP ★★` (agent 6)
`ext/concrete.model.yml:74`. `methodEntrypointModel` matches every method named `view()` in the codebase as an
unauthenticated entrypoint (unlike the suffix/prefix globs everywhere else).
- **Fix:** drop the bare `view` row; rely on the `action_%` dispatch row.

### T1-9. Dead `["function","settype"]` sanitizer row  `BUG ★` (agent 7)
`ext/php-builtins.model.yml`. `settype` returns bool and mutates by-ref; a `sanitizerModel` marks the bool
return, sanitizing nothing (the real handling is `SettypeBarrier` in QL). Also type-blind.
- **Fix:** remove the row (dead + misleading).

---

## TIER 2 — Dataflow engine (fan-out follow-ups, missing steps, perf)

### T2-1. The Batch-9 fan-out cap was not mirrored to the array-callable / function / try-catch resolvers  `FP/PERF ★★` (agent 4)
Three by-name resolution branches remain uncapped (the exact path-explosion Batch-9 targeted, via other doors):
- `TypeInference.qll:280-281` — array-callable virtual dispatch (`[$obj,'handle']`, `call_user_func([$obj,'handle'],…)`) has neither count cap nor name gate.
- `TaintTrackingPrivate.qll:156-163` — `resolvesToCallee` FUNCTION branch is ungated while the METHOD branch is gated (drives by-ref writeback / spread / named-arg steps → taint into all same-named function bodies).
- `DataFlowPrivate.qll:523-536` — try/catch callee resolution is name-only, uncapped, and inside a recursive predicate (wrong taint from unrelated classes' `execute()` + a join hotspot).
- **Fix:** apply the same `nameFallbackAcceptable`/count-≤8 gate (and prefer `TI::inferredMethod` when the receiver type is known) to all three — but with the P0-E cliff fix (rank/keep-N, don't null).

### T2-2. Query-builder fluent taint step omits UPDATE/INSERT setters  `FN ★★` (agent 4)
`TaintTrackingPrivate.qll:262-263`. The clause list is `where/andWhere/orWhere/having/order/orderBy/group/groupBy`
only. `$qb->update('u')->set('u.name',$_GET['n'])->getQuery()->execute()` drops taint before the sink — the whole
UPDATE/INSERT injection shape is missed while SELECT is covered.
- **Fix:** add `set`/`setValue`/`values`/`addSelect`/`select`/`join`/`innerJoin` (same "only alerts if it reaches a SQL sink" mitigation applies).

### T2-3. `getConstructCallee` resolves constructors by short class name only  `FP ★` (agent 4)
`DataFlowPrivate.qll:144-148`. `new App\Logger($x)` cross-connects to every class whose short name is `Logger`.
- **Fix:** resolve via `resolveClassReference(...)` like `exprClass`, or cap by count.

### T2-4. `static::m()` ignores late-static-binding overrides  `FN ★` (agent 4)
`TypeInference.qll:299-300`. `self`/`static` both map to the enclosing class, so `static::handle()` never reaches a
subclass override (the template-method pattern) and name-fallback is disabled once static resolves → FN.
- **Fix:** for `static::` (not `self::`), also dispatch to subtype declared methods of that name (capped).

### T2-5. Post-update caller-side step is O(reads²) with a transitive block-successor join  `PERF ★` (agent 4)
`DataFlowPrivate.qll:568-584`. `r2` ranges over every read of the same SSA version × `bb1.getASuccessor+()=bb2` —
a hotspot on framework methods with a heavily-reused `$this->db`/`$builder`.
- **Fix:** bound `r2` to the nearest dominated read, or use the SSA order already available from `ssaDefReachesRead`.

---

## TIER 3 — Access-control / IDOR (beyond P0-C)

### T3-1. `AccessControlTaint`'s `isNumericGuardedRead` is a stale copy of the OLD positive-only guard  `FN ★★` (agent 1)
`AccessControlTaint.qll:32-49`. IDOR never gets the Batch-3 polarity/early-exit logic, so
`if(!is_numeric($id)) return; delete($id);` — the dominant PHP validation idiom — leaves the read sanitized and
the IDOR is suppressed.
- **Fix:** mirror the full `isGuardedRead` (with the P0-B `&&`/`||` and P0-F SSA fixes) inside `isNumericGuardedRead`.

### T3-2. `callIn` leaks calls across nested-callable boundaries  `FN+FP ★★` (agent 3)
`AccessControl.qll:144-145`. `getParent+()` attributes a call inside a nested closure to the outer callable, so a
guard in a `register_shutdown_function(function(){ current_user_can(...) })` suppresses the unguarded action in the
handler (and mis-attributes actions). Falsifies the "same callable" comment at `:220`.
- **Fix:** nearest-enclosing-callable semantics (exclude calls inside an intervening `Callable`).

### T3-3. `directCallee`/`reaches` are namespace-blind → `reaches()` explodes → `hasGuard` over-suppresses  `FN+PERF ★★` (agent 3)
`AccessControl.qll:149-159`. Short-name resolution pulls in every function named `save`/`get`/`update`; since
`hasGuard(e)=isAuthorizationGuard(callIn(reaches(e)))`, some reached body almost always contains a guard → missing-auth
systematically suppressed, and `reaches`×`callIn` is a hotspot.
- **Fix:** scope name resolution by namespace/enclosing type; cap fan-out; key the guard search to the same reachable *path* as the action.

### T3-4. `propertyReceiverClassName` is flow-insensitive → unsound sanitizer coverage  `FN ★★` (agent 3)
`ModelExtensions.qll:191-205`. Resolves `$this->db`'s class from *any* `$this->db = new C()` in the class, with no
reaching-def. `$this->db = new Wpdb(); … $this->db = $userFactory; … $this->db->prepare($sql)` still marks the
now-unsafe `prepare` as a `TypedSanitizer` → real SQLi suppressed. (`receiverClassName` at `:157` uses SSA; this one doesn't.)
- **Fix:** require the property assignment to reach the use (SSA); don't treat as a definite sanitizer receiver when multiple classes are assigned.

### T3-5. `isSensitiveAction` discards `argIndex` → IDOR-only rows double-fire MissingAuthorization  `FP ★` (agent 3)
`AccessControl.qll:173-181,193-198`. A row authored purely for the IDOR variant (concrete `argIndex>=0`, e.g.
`"sensitive-read"`) also fires `missingAuthorization` at every call site; multi-category names duplicate findings.
- **Fix:** gate `missingAuthorization` to state-change/privilege categories (or `argIndex=-1` rows); dedupe per action call.

### T3-6. Idor & MissingAuthorization (`@precision medium`) are excluded from the default `php-code-scanning.qls`  `GAP med` (agent 9)
They're the only medium-precision queries; the default suite's `code-scanning-selectors` keep high/very-high only,
so BAC/IDOR never surface in ordinary scans (they do run in `php-security`/`-extended`/`-access-control`).
- **Fix:** raise to `high` (justifiable now guards are inter-procedural) or document that access-control needs the extended/dedicated suite.

---

## TIER 4 — Safe new capabilities (retire stale deferrals; additive, recall-monotone)

### T4-1. Tier-2-N (named-arg taint) is ALREADY IMPLEMENTED — retire the deferral  (agents 4, 9)
`TaintTrackingPrivate.qll:806-822` routes `f(cmd: $v)` to the parameter *named* `cmd`, callee resolved by
`resolvesToCallee` (typed, or name gated ≤8); `getArgumentCfgNode` (`DataFlowPrivate.qll:122-125`) excludes named args
from positional mapping. The stale comment at `:121-125` and the `PRECISION_AUDIT.md` deferral are wrong.
- **Action:** move Tier-2-N to "fixed"; add a probe to confirm.

### T4-2. StoredInjection → stored-XSS (CWE-79), currently entirely absent  `FN ★★` (agents 1, 9)
`StoredInjection.ql`. Fold in a *separate* config so the XSS barrier doesn't over-block the other kinds:
```ql
module StoredXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof StoredSource }
  predicate isSink(DataFlow::Node n)   { n.(Sink).getKind() = "reflected XSS" }
  predicate isBarrier(DataFlow::Node n){ n instanceof Sanitizer or n instanceof XssSanitizer }
}
```
Union the two PathGraphs in the select. `StoredSource` isn't a `RemoteFlowSource`, so no first-order flood; the
`XssSanitizer` barrier prevents the escape-then-store-then-echo FP that killed the naive single-config fold.

### T4-3. StoredInjection WRITE side has no barrier → over-approximates user-writable keys  `FP ★★` (agent 1)
`StoredInjection.ql:65-78`. `WriteConfig` lacks `isBarrier`, so a key whose every write path is sanitized/whitelisted
is still treated as user-writable → the read is an unconditionally-tainted `StoredSource` → SQL/deser/code FP.
- **Fix:** add `predicate isBarrier(DataFlow::Node n){ n instanceof Sanitizer }` to `WriteConfig`.

### T4-4. Tier-1-F negative type guard for Collection methods — safe partial  `FP ★` (agent 9)
Barrier the sink arg of the Collection-overlapping laravel methods (`where/pluck/max/min/…`) ONLY when the receiver
*provably* resolves (via `exprTypeName`) to `Collection`/`LazyCollection`/`Enumerable` or is a literal `collect(...)`.
**Recall-monotone:** vendor being unextracted, `exprClass` never resolves those, so it subtracts only type-annotated /
`collect()` FPs — the corpus's `DB::table()->where` (unannotated) can't regress. Same shape applies to the templating
bare-method SSTI sinks (`render`/`fetch` on `PDOStatement`/`mysqli_result`). Modest but zero-risk.

### T4-5. Tier-2-G POP-gadget flood — cheap partial  `FP ★` (agent 9)
`FlowSources.qll:44-49`. Give the magic-method field source a distinct `getSourceType()` (`"pop-gadget"`) and exclude
that type from `ReflectedXss`/`OpenRedirect`/`Ssrf` (a `__destruct` field reaching `echo`/`Location:` is noise, not the
POP threat model); keep it for deserialization/code/SQL/path. No engine change.

---

## TIER 5 — Lower-priority precision (FlowSources residuals + accepted tradeoffs)

- **[FN ★] `isGuardedRead` sanitizes ANY arg of a multi-arg guard** — `FlowSources.qll:142` `checked=g.getAnArgument()`; a later use of `preg_match($userPattern,$id)`'s `$userPattern`/`$haystack` is wrongly barriered → restrict to the guard's data arg (index-aware). (agent 2)
- **[FN ★] array_map barrier clears attacker-controlled KEYS** — `FlowSources.qll:195-204`; `array_map('intval',$_GET['data'])` then `foreach($out as $k=>$v) query($k)` → key injection missed → model as a value-only step, not a whole-array barrier. (agent 2)
- **[FP ★] `RequestPropertySource` taints Symfony bag *objects*** — `FlowSources.qll:640-653` excludes neither `query`/`request`/`attributes`/`cookies`/`files`; `$request->query` is an `InputBag` object, not a value (the real flow is via `->query->get()`, already handled) → add them to the exclusion list. (agent 2)
- **[FN ★] `<?=` short-echo XSS sink misses whitespace/newline gap** — `FlowSources.qll:364-371` requires same line + ≤3 cols; `<?=\n    $x ?>` fails → match the first non-whitespace token after the tag. (agent 2)
- **[FN ★] `sinkFunctionKind` only reads argIndex `-1`** — `FlowSources.qll:213`; a function sink pinned to a specific arg is invisible to string-callable/`call_user_func` dispatch → look up any argIndex. (agent 2)
- **[FP ★] Moodle `optional_param`/`required_param` unconditional source** — `ext/moodle.model.yml:6-10`; `PARAM_INT`/`PARAM_ALPHANUM` callers are SQL-safe → a kind-aware `MoodleParamSource` keyed on the constant arg2 (like `GetpostSource`). Recall-safe as-is; low priority. (agent 6)
- **[FP note] array-condition query builders** — craftcms `Query.where` (`:17-19`), mediawiki `select`/`update` `$conds` (`:21-30`), typo3 QueryBuilder (`:58-69`) flag the *parameterised array* form (`->where(['c'=>$x])`); needs a query-side barrier exempting array-literal args with constant keys (mirror `$wpdb->prepare`). Not fixable by a row edit. (agent 6)
- **[BUG ★] `argOf(-2)` is dead for `staticmethod` rows** — `ModelExtensions.qll:221-229` casts to `MethodCall` but `StaticMethodCall` isn't one; `DataStep` also can't do `toArg=-2` → document `-2` as method-only or handle it. (agent 3)
- **[FP ★ — accepted] generic escaper STEP names** (`element`/`entities`/`purify`/`specialchars`) carry taint on any receiver — low severity (steps only add edges); scope to the CMS class if a typed row exists. (agent 8)
- **[FP — documented tradeoff] `DOMXPath::query` double-classified** SQLi + xpath (`modern-frameworks:24` vs `php-builtins:357`); e107/suitecrm `save`/`retrieve`/`count` bare sensitive-actions/sinks — all instances of the recall-first bare-method policy `PRECISION_AUDIT.md` already documents. (agents 6, 7)
- **[LOW] `methodEntrypointModel` globs `execute`/`resolve`** as unauth entrypoints — intended per-app, noisy on mixed DBs; pairs badly with T3-6. (agent 9)
- **[architectural] SQL-only escapers hide escape-then-XSS** (`pSQL`/`bqSQL`, `escapeField`/`escapeTable`, `quoteIdentifier`) — the mirror of the HTML-escaper problem; the real fix is the long-deferred per-kind `vulnKind` column on `sanitizerModel`. (agents 5, 7)

---

## Cross-cutting root causes (fix once, resolve several)

1. **Barriers match tainted reads by variable NAME with no SSA/kill** → P0-B, P0-F, T3-1, plus the array_map key case. A single SSA-based `sameAccessPath`/`readAfterInSameBlock` (share the guarded value's SSA def; bail on intervening reassignment) closes the guard-`&&/||`, reassignment, and IDOR-guard defects together.
2. **Short-name / namespace-blind resolution** → P0-D (ancestor arm), T2-1/T2-3 (callee resolution), T3-3 (reaches), P0-A (`functionDefinedInSource`). Resolve by FQ name / distinctive class names and cap fan-out uniformly.
3. **`sanitizerModel` has no `vulnKind`** → the whole escaper-classification churn (T1-2/3/4/5, the SQL-escaper-then-XSS residual). The proper fix is the deferred per-kind sanitizer column; the interim weak-XSS+step pattern must be applied *consistently* (it currently has gaps: laravel `e`, wp `wp_kses`/`esc_js`, symfony/builtins bare `escape`).
4. **Numeric barriers not shared with the IDOR engine** → P0-C, T3-1. The AC taint config must subtract the same coercion barriers the injection engine gained.

---

## Appendix — verified SOLID under adversarial review (no action)

Batch 1 (model corrections), Batch 2 (core HTML-escaper reclassification — free functions, arg0 steps correct),
Batch 6 (`FilterVarNumericBarrier`; the `/e` delimiter regex is anchored/sound; OpenRedirect `[/?#]` is a strict
improvement), Batch 7 (`benignConstStr` for string operands + WeakRandom direct-assign) were each attacked and held.
The `NumericCastSanitizer` / `ScalarParamBarrier` / `sprintf` (except the custom-pad edge P0-I) barriers are sound
*as injection barriers* — their only defect is not being shared with the IDOR engine (P0-C).

*Methodology: 9 static-analysis agents (query files; FlowSources; ModelExtensions+AccessControl; dataflow engine;
flagship models; remaining CMS models; builtins+cross-cutting; adversarial review of the 9 batches; deferred-item
feasibility + new systemic), current tree, no DB builds. Cross-corroboration noted per finding.*
