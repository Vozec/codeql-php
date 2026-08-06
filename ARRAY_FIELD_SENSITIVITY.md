# Array field-sensitivity (Tier 6-2) — execution-ready plan

The **last structural precision item**. Fully de-risked by a dedicated research agent (the whole-array
consumer enumeration below is the FN-prevention checklist). NOT yet implemented — this is a staged,
recall-corpus-validatable but FP-UNMEASURABLE-here change, so it belongs in a dedicated session with an
FP-validation harness. Everything needed to execute safely is captured here.

## Problem
`TContent = TArrayContent() | TFieldContent(name)` (`DataFlowPrivate.qll:410-412`) — ONE bucket for ALL array
elements. So `$a['x'] = $tainted; $a['safe'] = 'literal'; sink($a['safe'])` reports a FP: `$a['safe']` is
tainted by `$a['x']`'s value through the shared bucket. Object fields are already per-name
(`TFieldContent(name)`), so `$o->x`/`$o->safe` don't cross-contaminate — arrays should match.

## Why it's genuinely risky (the trap the round-1/2 audits missed)
`defaultImplicitTaintRead = none()` (`TaintTrackingPrivate.qll:914-918`), so content taint is NOT
auto-flattened to node-level. Any consumer that reads the **whole-array NODE** (not via `readStep`) sees taint
only when the node is NODE-level tainted. The moment a constant-key store `$a['x']=taint` is narrowed from the
shared `TArrayContent()` to a per-key `TArrayKeyContent('x')` bucket (Stage 2), the array NODE is no longer
node-tainted → every whole-array consumer silently drops the flow = **FN**. Each such consumer must first be
converted to an **all-keys content read** (read `TArrayContent()` ∪ every `TArrayKeyContent(_)`).

## Design
```
newtype TContent =
  TArrayContent() or                                     // dynamic / unknown-key bucket (KEEP)
  TArrayKeyContent(string k) { k = anyArrayConstKey() } or
  TFieldContent(string name) { ... }
```
- `anyArrayConstKey()` = integer-literal or `constStringText`-style key (INTERPOLATION-REJECTING — the P0-H
  lesson: `$a["p$x"]` must NOT yield `"p"`, or a dynamic key masquerades as constant and taint mis-files).
- `getContentApprox`: map BOTH `TArrayContent` and `TArrayKeyContent(_)` → `TArrayContentApprox()` (coarse
  stage stays cheap and a sound over-approximation).

### Read/store invariants (recall-critical)
- **Constant-key STORE** `$a['x']=v` → `TArrayKeyContent("x")` (Stage 2) [Stage 0: BOTH it and `TArrayContent()`].
- **Dynamic/append STORE** `$a[$k]=v` / `$a[]=v` / spread / keyless literal element → `TArrayContent()`.
- **Keyed array-literal** `['x'=>v]` → `TArrayKeyContent("x")`; keyless element → `TArrayContent()`.
- **Constant-key READ** `$a['x']` → read `TArrayKeyContent("x")` AND `TArrayContent()` (the shared arm is
  MANDATORY: a prior dynamic-key store landed in `TArrayContent()` and could alias `'x'`).
- **Dynamic-key READ** `$a[$k]` → read `TArrayContent()` AND EVERY `TArrayKeyContent(_)` (constant stores went
  to per-key buckets, so an unknown-key read must consult them all).

## Staging (corpus-gated — 201/201 must hold after every stage)
- **Stage 0 — write-BOTH / read-BOTH.** Constant store → both `TArrayKeyContent(k)` and `TArrayContent()`;
  constant read → specific + shared; dynamic read → shared + all-keys. Provably a **no-op** (every value still
  reaches `TArrayContent()`, every read still consults it). Lands the type machinery. Verify 201/201 bit-identical.
- **Stage 1 — convert the whole-array CONSUMERS below** to all-keys content reads. Recall-monotone.
- **Stage 2 — narrow** constant-key stores to `TArrayKeyContent(k)` ONLY (drop the shared-bucket write). The
  SINGLE FN-risky step — the corpus is the recall harness; the checklist below is what prevents the drops. The
  FP *payoff* is unmeasurable on this corpus (no benign-array test cases) — needs an FP harness to quantify.

Edit points: `DataFlowPrivate.qll` (`TContent` :410, `getContentApprox` :448, `readStep` :709/717, `storeStep`
:727/737/743/750), and the consumers below.

## WHOLE-ARRAY CONSUMER CHECKLIST (Stage-1 — each MUST become an all-keys content read)

### Engine steps — `TaintTrackingPrivate.qll` `defaultAdditionalTaintStep`
1. `foreach($a as $v)` / `$k=>$v` / `as [$x,$y]` — **L331-333** (whole collection → binding, plain edge).
2. by-ref foreach `as &$v` write-back — **L338-348** (store side).
3. `list()/[..]` destructuring `[$a,$b]=$rhs` — **L388-391**.
4. `extract($arr)` — **L492-502** (ideally each var reads `TArrayKeyContent(varname)`; all-keys is the safe floor).
5. generator `yield`→`foreach(g() as $v)` — **L504-512** (align with #1).
6. higher-order callback data→param (`array_map(fn($x)=>…,$a)`, `usort`) — **L694-704**.
7. `array_walk`/`array_walk_recursive` by-ref cb — **L720-737** (store side, family of #2).
8. `call_user_func_array` args→params — **L804-807** (+ result twin L787-789).
9. spread / variadic unpack `f(...$args)` — **L814-821**.

### `(array)`/`(object)` casts
10. `Php::CastExpression` via `structuralPropagator` **L874** + recursive step **L261-265** — node-level only;
    content lost across the cast. Lower priority (node-level taint still flows).

### Whole-array BUILTINS — `stepModel` rows via `DataStep` (`ModelExtensions.qll:316-329`, all plain `-1→-1`)
`ext/php-builtins.model.yml`: `implode`/`join` (L286-287); `array_map`/`array_filter`/`array_reduce`
(L324-328); `array_values`/`array_keys`/`array_merge`/`array_merge_recursive`/`array_replace`/`array_slice`/
`array_splice`/`array_reverse`/`array_unique`/`array_flip`/`array_pad`/`array_combine`/`array_column`/
`array_chunk`/`array_diff`/`array_intersect` (L336-352); `current`/`reset`/`end`/`array_shift`/`array_pop`
(L354-358). These need either per-row content annotation or a content-aware `DataStep` variant for array builtins.

**Highest-risk if skipped:** #9 spread, #6 array_map-callback, #1/#3 foreach+list, and `implode`/`array_merge`/
`array_values` (SQL/HTML sink concatenation of a keyed request array).

### ALREADY SAFE (rely on the core `readStep`/`storeStep` — not a separate conversion)
Subscript read `$a['x']` (`readStep` L709), subscript/literal/`.=`/`+=` store (`storeStep` L717-747),
string-interpolated `"$a[x]"` (parsed as a `SubscriptExpression` — CONFIRM the tree-sitter node during
Stage-1), the subscript-base→result over-approx edge (L269-271, node-level), and the array-literal recursive
propagator (L261-265, source side).

### Template
Object fields (`TFieldContent(name)`, `readStep` L708-714, `storeStep` L728-767, `TFieldContentApprox` L426-448,
`clone` content-preserving step L579-581) are the store/read-partitioning template — mirror them. But objects
have NO whole-object consumer-conversion analogue, so items #1-#9 + the builtins are genuinely new work; this
checklist is the substitute.

*Prepared from a dedicated research agent's static enumeration of the current tree; no DB builds.*
