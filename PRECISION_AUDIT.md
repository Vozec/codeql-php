# PHP CodeQL fork — precision & correctness audit

Deep review by 9 parallel analysts over the queries, taint libs, dataflow engine, and 39 model
files, plus 2 empirically-confirmed findings (built a real DB + ran the suite). Goal: **not more
frameworks — cover better**: kill false positives (too-lax), recover false negatives (too-strict),
fix bugs. `[✓CONFIRMED]` = reproduced empirically. `[MINE]` = introduced by the recent CMS branch.

Legend: **FN** = misses real vulns (too strict) · **FP** = fires on safe code (too lax) · **BUG** ·
**PERF**. Severity ★★★ high / ★★ med / ★ low.

---

## TIER 1 — Systemic, highest impact (each found by multiple analysts)

### A. `sanitizerModel` is context-blind (no `vulnKind`) → escapers barrier EVERY vuln class  `FN ★★★`
*Found independently by 4 analysts.* A `sanitizerModel` row is a barrier for **all** queries, so an
HTML/shell/SQL escaper wrongly neutralizes unrelated classes → the whole **escape-then-inject** class
is missed.
- `php-builtins.model.yml:141-150` — `htmlspecialchars/htmlentities/strip_tags/esc_html/esc_attr/esc_url/esc_js/wp_kses*/sanitize_email` as FULL sanitizers block SQLi/RCE/path. e.g. `system("ping ".strip_tags($_GET['h']))` with `h=";id"` → **not reported**.
- `php-builtins.model.yml:151-157` — `escapeshellarg/cmd` block SQLi/XSS; `mysqli_real_escape_string/addslashes/pg_escape*` block command/path/code.
- `php-builtins.model.yml:165-168` — `basename/realpath` (path-only) + `preg_quote` (regex-only) block everything.
- `php-builtins.model.yml:144-145` — **`esc_html`/`esc_attr` are double-declared**: the full-sanitizer builtin row OVERRIDES `wordpress.model.yml:59-60`'s deliberate weak-XSS+step fix (comment cites CVE-2024-1071 / CVE-2022-0169) → the campaign's own escape-then-SQLi detection is silently dead.
- Per-CMS HTML escapers as full sanitizers (same bug): `magento:81-88` (escapeHtml/Js/Css/Url…), `yii:33` (Html::encode — also over-generic name), `cakephp:29` (`h`), `codeigniter:32-33` (html_escape/xss_clean), `drupal:62-68`.
- **Fix:** give `sanitizerModel` a `vulnKind` column (mirror `sinkModel`) and gate each query's barrier on kind. Interim (no engine change): move the HTML/JS/URL escapers to `weakXssSanitizerModel` + a `stepModel arg0→-1`, keep genuinely multi-context ones (`intval`, `md5`, `base64_encode`) global.

### B. `isGuardedRead` ignores guard polarity & control-flow  `FN+FP ★★★`  [✓CONFIRMED]
`FlowSources.qll:83-93`. The guard call is matched anywhere in the `if` condition with no polarity/
dominance check.
- **Polarity FN [✓]:** `if(!ctype_digit($id)){ $db->query("…$id"); }` — the *dangerous* branch (id NOT numeric) is marked sanitized → **missed SQLi** (empirically: no finding).
- **Early-return FP [✓]:** `if(!ctype_digit($x)) return; sink($x);` — the guarded value is NOT recognized (only the then-branch is) → **safe code flagged** (empirically: fires). This is the *dominant* PHP validation idiom.
- Also misses `else`-branch and `&&` chains.
- **Fix:** reject a guard sitting under `!`/top-level `||`; add a dominance arm for `if(!g($x))return/throw/die;` guarding everything after.

### C. `functionDefinedInSource` disables real framework sanitizers on whole-CMS scans  `FP ★★★`
`ModelExtensions.qll:286-299`. A `function` sanitizer is suppressed if a function of that name is
*defined in the analysed source*. PHP can't redefine globals, so this fires on the **genuine framework
definition** — e.g. scanning WordPress core (which defines `esc_sql`, `sanitize_email`) turns those
sanitizers OFF → every escaped query false-fires on the exact wp2shell target.
- **Fix:** suppress only when the in-source body is a trivial pass-through (returns its param unchanged); or keep a curated always-trust set; or make the MAD sanitizer *additive* (row OR real-body).

### D. Typed **sanitizer** receiver resolution is weak while typed sink/source is strong  `FP ★★`
`ModelExtensions.qll:207-219` `TypedSanitizer` uses only `receiverClassName` (`new C()`/literal `$wpdb`)
+ `exprTypeName` + `propertyReceiverClassName`(wpdb only), whereas typed sinks/sources use the strong
`receiverIsClass` (inference + ancestors + typehint). So a DI/factory-injected `$this->db->prepare($sql)`
isn't seen as a sanitizer → parameterized query flagged SQLi.
- **Fix:** route `TypedSanitizer` through the same `receiverIsClass` predicate.

### E. Access-control guard = "exists anywhere", not "dominates the action"  `FN+FP ★★★`
`AccessControl.qll:162-197,225-228`.
- **Wrong-capability FN:** `if(!current_user_can('read')) wp_die(); … wp_delete_post($_POST['id']);` — the `read` check satisfies `hasGuard`, so the missing `delete_posts` check is never reported (the dominant WP bounty class). The authors *documented* rejecting transitive reach for IDOR (`:219-223`) but `hasGuard` does exactly that → the two sibling queries contradict.
- **Generic-name FP/FN:** guards (`can`/`access`/`check`) and sensitive actions (`remove`/`store`/`save`) matched by **bare method name on any receiver** → `$cache->remove($k)` is a "sensitive action", `$validator->check()` "authorizes".
- `reaches()` follows **global functions only** → method-delegated guards/actions in OO CMS (PrestaShop/Magento/Symfony) are invisible.
- **Fix:** dominance-based guard (CFG); typed guard/action models (`typedAuthorizationGuardModel`); add receiver-typed method-callee to `reaches()`. Unify Idor & MissingAuthorization on one guard predicate.

### F. Over-broad **bare-method sinks** collide with unrelated classes  `FP ★★★`
`sinkModel` matches a bare method name on ANY receiver.
- `laravel.model.yml:115-130` — `where/pluck/max/min/avg/sum/select/orderBy/groupBy/to` fire on in-memory `Illuminate\Support\Collection` (used everywhere) and on builder arg0 which is a literal *column* (the tainted value is the parameterized arg1). **Biggest FP cluster.**
- `modern-frameworks.model.yml:24-25` — `query`/`exec` on any receiver (`DOMXPath::query`, `Redis::exec`).
- `wordpress.model.yml:11-14` — `get_results/get_var/get_col/get_row` at `-1` on any receiver (should be `typedSinkModel("wpdb",…,0)`).
- `prestashop:24` `getRow -1`, `concrete:30-33` `GetRow/GetOne/GetAll/GetCol`, `joomla:37`/`symfony:64` `redirect`, `typo3:75` `request`.
- **Fix:** convert generic names to `typedSinkModel` scoped to the real DB/HTTP class; pin `-1`→`0`.

---

## TIER 2 — High value

| # | Cat | Sev | Location | Issue → Fix |
|---|-----|-----|----------|-------------|
| G | FN | ★★ | POP-chain source `FlowSources.qll:42-47` | Every `$this->field` in ANY `__destruct/__wakeup/__unserialize` is a GLOBAL `RemoteFlowSource` → flooding all queries on cleanup destructors. **Fix:** gate to a deserialization-only source type, or to classes reachable from `unserialize` of tainted data. (3 analysts) |
| H | FP+PERF | ★★ | `TypeInference.qll:242-247` + `DataFlowPrivate.qll:253` | Base/interface receiver dispatches to **every** subtype's method, uncapped (name-fallback IS capped at arity≤8). `LoggerInterface->handle($sql)` connects 30 unrelated bodies → path explosion. **Fix:** apply the arity cap to the subtype-fanout branch. |
| I | FP | ★★ | `php-builtins.model.yml:230-231` | `sprintf('%d',$x)` stays tainted — the canonical safe `sprintf('… id=%d', $_GET['id'])` flagged SQLi. **Fix:** barrier a sprintf whose constant format has only numeric specifiers (no `%s`). |
| J | FN | ★★ | `php-builtins.model.yml` steps | Missing carriers `mb_substr/mb_strtolower/mb_convert_*/iconv/strstr/stristr/preg_filter` (ubiquitous in i18n/CMS) → taint drops. **Fix:** add `[-1,-1]` step rows. |
| K | FN | ★★ | `php-builtins.model.yml:167` | `filter_var` unconditional sanitizer — `FILTER_VALIDATE_URL` returns input unchanged → SSRF FN; `FILTER_DEFAULT`/`UNSAFE_RAW` is a no-op. **Fix:** only barrier for genuinely-neutralizing filter constants, kind-scoped. |
| L | FN | ★★ | weak-XSS **without paired step** (taint drops) | `suitecrm:19-24` (entry-wide `securexss`/`cleanHtml` — whole-corpus FN), `mediawiki:51-56`, `processwire:43-47`, `concrete:40-44`, `textpattern:30-33`, `craftcms:29-31`. **Fix:** add `stepModel arg0→-1` for each. [several MINE] |
| M | FN | ★★ | `drupal.model.yml:69` `escapeLike` FULL sanitizer | LIKE-wildcard escaper (not quotes) modeled as full barrier → concatenated-LIKE SQLi missed. Inconsistent with WP/TYPO3/Dolibarr which use a STEP. **Fix:** move to `stepModel`. |
| N | FN/BUG | ★★ | `DataFlowPrivate.qll:121-125` | Named args (`f(b: $input)`) carry NO taint — the "compensating step" the comment promises doesn't exist. **Fix:** add named-arg→matching-param step. |

---

## TIER 3 — Concrete bugs (mostly quick, high-certainty)

| # | Cat | Location | Bug → Fix |
|---|-----|----------|-----------|
| 1 | BUG/FN | `php-builtins.model.yml:126-129` | LDAP sinks emit kind **`"LDAP injection"`** but the query matches **`"ldap injection"`** → 4 DEAD rows; **`ldap_bind` has no live sink** (auth-bypass FN). Fix: lowercase + add `ldap_bind` DN. |
| 2 | BUG | `concrete.model.yml:35-37` [MINE] | `["Redirect","url",…]`/`["AbstractController","redirect",…]` put in `sinkModel` (subjectKind must be method/function/staticmethod) → **3 DEAD rows**. Fix: `typedSinkModel`. |
| 3 | FP | `php-builtins.model.yml:134` | `unserialize` at `-1` flags the safe `unserialize($x, ['allowed_classes'=>false])` and mis-targets the options arg. Fix: argIndex `0` + barrier when `allowed_classes=>false`. |
| 4 | BUG | `php-builtins.model.yml:227` | `str_contains 0→-1` step propagates taint from a **boolean** result. Fix: remove. |
| 5 | BUG | `php-builtins.model.yml:158` | `["function","quote"]` — no such PHP builtin → dead row. Fix: remove. |
| 6 | FP | `crypto.model.yml:11` | `encrypt -1` flags constant **plaintext** as a hardcoded key. Fix: pin the key arg. |
| 7 | BUG | `modern-frameworks.model.yml:33` | `getResult -1` — Doctrine `getResult()` runs an already-built query; arg is a hydration int, never SQL. Fix: remove. |
| 8 | FP | `FlowSources.qll:441-449` | `loadHTML` listed as an XXE sink — HTML loading doesn't expand XML entities. Fix: drop from XXE method list. |
| 9 | FP | `FlowSources.qll:14` | `$_ENV` is an unconditional source, inconsistent with the `$_SERVER`/`getenv` constant-key splits. Fix: same split. |
| 10 | FP | `modern-frameworks.model.yml:55-58` | `getInt/getBoolean/getAlpha/getDigits` modeled as **sources** (they type-coerce → non-injectable) and conflict with `getInt`-as-sanitizer in joomla/xoops/mediawiki. Fix: delete the source rows. |
| 11 | BUG | `prestashop.model.yml:38-43` vs `60-65` [MINE-merge] | Duplicate `Db/DbCore execute/getValue` typedSink block. Fix: dedupe. |
| 12 | FN | `FlowSources.qll:41` vs `43` | `__toString` listed as POP source in the comment, absent in code. Fix: reconcile. |

---

## TIER 4 — Query-specific precision

- **TypeJuggling** `TypeJuggling.ql:24-33` — name branch too broad (`$passes==3`, `$token==''`, `$hash_algo=='sha256'` all fire at @precision high) **and** misses `in_array($x,$y)` (loose by default), `array_search`, loose `switch`. Fix: require the *other* operand to be non-literal-string; add `in_array`/`switch`.
- **WeakSecurityRandomness** `:26,53-61` — misses un-hashed token assignment (`$token=mt_rand()`) and bare `uniqid()` source (`md5(uniqid())`). Fix: add direct-assignment sink + `uniqid` source.
- **OpenRedirect** `OpenRedirect.ql:26-31` — host-pin barrier regex lacks a trailing `/`, so `header("Location: https://good.com".$_GET['x'])` (→ `good.com.evil.com`) is suppressed. Fix: require `://host/`.
- **StoredInjection** `:96-98` — second-order read can't reach XSS/echo sinks (stored-XSS gap; CWE-79 absent). Fix: add `reflected XSS` kind (XSS-barriered).
- **preg_replace `/e`** `FlowSources.qll:481-487` — delimiter class `[/#~!@%|]` misses comma/bracket delimiters → `preg_replace('(x)e',…)` RCE missed. Fix: broaden delimiters.
- **templating** `templating.model.yml:17-27` — `render/fetch/display/compile` as bare template-injection sinks (severity 9.3) fire on `$pdf->render`, PDO `fetch`. Fix: type-scope to Twig/Smarty/Blade.
- **Array field-insensitivity** `DataFlowPrivate.qll:387-745` — single `TArrayContent` bucket leaks taint across keys (`$a['safe']` tainted by `$a['x']`). Fix: key on constant subscripts + one dynamic fallback bucket.
- **Ungated string/FCC callables** `DataFlowPrivate.qll:171-185,800,821` + **uncapped try/catch** `:520-533` — resolve by bare name over all callables. Fix: apply `nameFallbackAcceptable`.

---

## TIER 5 — Recent-branch (my) regressions to tighten  [MINE]

- `FlowSources.qll:514-519` — `->request` on **any** `::$prop` scoped-property treated as HttpFoundation Request (comment says "Yii/Craft" but code is unscoped). Fix: constrain scope name to `["Yii","Craft"]`.
- `FlowSources.qll:695-705` — Dolibarr `GETPOST(...,'restricthtml'|'nohtml'|'alphanohtml')` treated as fully SQL-safe (they're HTML-only) → SQLi FN. Fix: kind-aware suppression (only int/aZ09 for SQL).
- `FlowSources.qll` `SettypeBarrier` — line-number ordering is CFG-blind: a `settype` inside `if($c){}` over-clears a later use on the `$c==false` path → FN. Fix: SSA/dominance instead of line numbers.
- `FlowSources.qll:128-133` `array_map` barrier — only a string-literal callback; misses first-class `array_map(intval(...),…)` (helper `firstClassCallableName` exists, unused), closures, `[$o,'m']`. Fix: reuse `firstClassCallableName` + route array_map data through the callback.
- `FlowSources.qll` `ScalarParamBarrier`/`paramReassigned` — stacked `getParent+()` closures → PERF hotspot on large DBs. Fix: scope via enclosing-callable relation.

---

## Cross-cutting recommendations (biggest leverage first)
1. **Add `vulnKind` to `sanitizerModel`** (or bulk-move HTML escapers to `weakXssSanitizerModel`+step) — resolves Tier-1-A + Tier-2-L/M + several Tier-3; the single largest recall recovery.
2. **Rewrite `isGuardedRead`** with polarity + early-return dominance — fixes Tier-1-B (both FN and FP) and underpins the access-control layer.
3. **Fix `functionDefinedInSource`** (trivial-passthrough / additive) — un-breaks whole-CMS scans (Tier-1-C).
4. **Unify receiver resolution** — one `receiverIsClass` for typed sinks, sources, AND sanitizers (Tier-1-D).
5. **Type-scope the over-broad bare-method sinks/guards/actions** (Tier-1-F, Tier-1-E) — the largest FP reduction.
6. Sweep the concrete bugs (Tier-3) — cheap, high-certainty.

*Methodology: 9 static-analysis agents (queries, FlowSources, ModelExtensions+AccessControl, taint
steps, dataflow engine, 39 model files ×2); 2 findings reproduced on a real CodeQL DB.*

---

## IMPLEMENTATION STATUS (9 verified batches — corpus held at 201/201, 0 un-annotated throughout)

**Fixed & verified** (each with a targeted before/after probe + full corpus run):

| Item | Batch | What landed |
|------|-------|-------------|
| Tier-3 (all 12) | 1 | dead/wrong/FP model rows: concrete Redirect→typedSink, unserialize -1→0, LDAP dead rows + `ldap_bind`, `encrypt`/`getResult`/`str_contains`/`quote` removed, loadHTML XXE, `$_ENV`, getInt sources, prestashop dedupe, `__toString` |
| Tier-1-A | 2, 4 | core + per-CMS HTML escapers → weak-XSS + carry-taint step (magento/yii/cakephp/codeigniter/drupal/wp), escape-then-inject now caught |
| Tier-1-B | 3 | polarity- & early-exit-aware `isGuardedRead` (FN + FP, both empirically confirmed) |
| Tier-1-C | 5 | `functionDefinedInSource` gated to trivial-passthrough only (un-breaks whole-CMS scans) |
| Tier-1-D | 5 | additive `TypedSanitizerStrong` via `receiverIsClass` (DI/factory receivers) |
| Tier-2-H | 9 | subtype virtual-dispatch fan-out capped (+ string-callable / Closure::fromCallable caps) |
| Tier-2-I | 5 | numeric-`sprintf` barrier |
| Tier-2-J | 4 | mb_*/iconv/strstr/preg_filter carriers |
| Tier-2-K | 6 | `filter_var` flag-aware (numeric-only barrier; else taint step) |
| Tier-2-L | 4 | paired carry-taint steps for weak-XSS-without-step (suitecrm/mediawiki/processwire/concrete/textpattern/craftcms) |
| Tier-2-M | 4 | drupal `escapeLike` → step |
| Tier-4 (subset) | 6, 7, 9 | preg_replace `/e` delimiters, OpenRedirect host-terminator, TypeJuggling benign-literal FP, WeakRandom uniqid+direct-assign, string/FCC/Closure callable caps |
| Tier-5 (subset) | 1, 4, 8 | array_map first-class callable, Yii `::$app` scope, Dolibarr GETPOST kind-awareness, settype CFG dominance |

**Deliberately NOT changed** (constraint documented, would do harm):

- **Tier-1-F (bare-method → typed sinks)** — the fork has **no `vendor/` extraction**, so factory/DI receiver
  types don't resolve. The corpus PROVES a typed conversion regresses to FNs: the voyager column-SQLi
  (`DB::table()->where($col)`) and all 3 template-injection tests (`$twig->render`, `Blade::render`) rely on
  bare-name matching. The bare-method sinks + their FP cost (Collection::where, PDO::fetch) are a deliberate,
  corpus-validated recall-first trade. Templating type-scoping fails the same way.
- **Tier-1-E (access-control dominance)** — `AccessControl.qll` is a finely-tuned FP/FN balance (its comments
  document approaches tried & rejected). The proper fix (CFG dominance + capability-argument matching + typed
  guard models) is a delicate rework, and the corpus has **0 missing-authorization annotations** (only 2 IDOR),
  so an FP/FN trade there can't be validated here. Switching `hasGuard` to same-callable would wrongly drop the
  legitimate guard-in-caller suppression. Left intact rather than regress a tuned subsystem blind.
- **Tier-2-G (POP-gadget source flood)** — a sound gate needs call-graph reachability from a *tainted*
  `unserialize`; a blind global gate either still floods or drops real `__destruct`/`__wakeup` gadgets.
- **Tier-2-N (named-arg taint)** — a call resolves to multiple callees with different parameter orders, so the
  named-arg→parameter routing must be per-callee inside the engine's argument-passing (not a flat taint step);
  a wrong step routes taint to the wrong parameter.
- **Tier-4 array field-sensitivity** — deep `DataFlowPrivate` content-model change, unvalidatable for FPs here.
- **Tier-4 StoredInjection→XSS** — needs a *separate* XSS-barriered flow config (folding `reflected XSS` into
  the existing config would either re-introduce escape-then-inject (Batch 2 regression) or FP on escaped output).
- **Tier-5 ScalarParam perf** — perf-only; no enclosing-callable API exists to replace `getParent+()`, and the
  corpus shows no timeout. Not worth a behavior-risking rewrite.
