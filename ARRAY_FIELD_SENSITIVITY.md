# Array field-sensitivity — the sibling-constant-key FP (SHIPPED)

Status: **implemented** on `feat/array-field-sensitivity` as a MUST-analysis barrier in
`php/ql/lib/codeql/php/security/FlowSources.qll` (`ConstantSiblingKeyBarrier`). Corpus 201/201, 0 FP;
FP + FN harnesses (`scratchpad/arr`, `scratchpad/arr2`) green.

## Problem
The engine's array handling is FIELD-INSENSITIVE for recall. Two content-INsensitive, node-level
mechanisms cooperate:

- **(A) element write re-taints the whole container.** `simpleAssignment` nested re-definition
  (`DataFlowPrivate.qll`) + the SSA partial-update (`updateBaseVariable`, `SsaImpl.qll`) make
  `$d['name'] = $_GET[...]` mark *all* of `$d` at node level.
- **(B) element read inherits the base's node taint.** The subscript base→result taint step
  (`TaintTrackingPrivate.qll:269`) propagates any node taint on `$d` to `$d[K]` for every `K`.

Together they FP on a sibling constant key:
```php
$d['name']  = $_GET['name'];   // (A) taints $d
$d['table'] = 'users';         // constant
$db->query("… " . $d['table']);   // (B) FP: 'users', not attacker data
```

## Why the content-bucket approach was abandoned
The "obvious" fix — split `TArrayContent()` into per-key `TArrayKeyContent(k)` buckets like object
`TFieldContent(name)` — was implemented and measured **inert**: mechanisms (A) and (B) are node-level and
short-circuit the content stage entirely (Stage-0 write-both was a verified no-op; the FP still fired).
Making the buckets bite would require ALSO removing (B) and re-routing EVERY whole-array/whole-value
consumer (foreach, implode, array_*, json_encode, http_build_query, interprocedural pass-through, …)
through content reads — because `$_GET` is a node-level source and superglobal element reads `$_GET['id']`
depend on (B). That is a broad, high-FN-risk engine rework. Reverted.

## Shipped solution — `ConstantSiblingKeyBarrier` (a pure MUST-analysis)
Neutralise a read `$base[K]` (constant key chain, RECURSIVE — `$e['sub']['table']`) ONLY when it can
PROVE the value is constant:

1. **Proven constant:** some assignment writes this *exact* cell a constant literal
   (`sameConstChain(w.getLhs(), r) and isConstLiteral(w.getRhs())`).
2. **No possible taint** (`cellPossiblyTainted(r)` is false):
   - no non-constant plain assign to this cell or an ANCESTOR (`$d['table']=$x`, `$e['sub']=$x`, `$d=$_GET`);
   - no augmented / reference assign to this cell or an ancestor;
   - no DYNAMIC-key / append / non-constant-chain write to the same root (`$d[$x]=…`, `$d[]=…`) — a dynamic
     segment could alias the cell;
   - the root is not iterated by-reference (`foreach($d as &$v)`) nor rebound via `global $d`;
   - **no ancestor (up to the root array) is passed DIRECTLY as a call argument** — the callee could take
     it by reference and mutate an element (`parse_str($q,$d)`, `sort($d)`, a user `function f(&$a)`), a
     taint the engine DOES model. Found by the arr6 harness: without this guard the barrier suppressed the
     `parse_str`/whole-array-by-ref FNs. The sink passes the value inside a larger expression
     (`query("…".$d['k'])`), so its argument is that expression, not the bare cell — it doesn't trip this.

`isConstLiteral` also recognises constant BINARY expressions (`'pre'.'fix'`, `60*60`) so a constant-concat
table name is provably constant (arr5 K1/K2); sound because every operand is itself proven constant.

Because it only ever REMOVES a flow it has proven safe, an unseen taint source just leaves the flow in
place → **no false negative**. The corpus (201 CVEs) is the recall guardrail.

Key helpers (all in `FlowSources.qll`): `strictSubscriptKey` (rejects interpolated keys), `constChainKey` +
`constChainScope` (the functional-key pair — see Performance), `sameConstChain`, `ancestorOrSelf`,
`chainRoot`, `isConstLiteral` (scalars + all-constant array literals + constant binary exprs so `[]`,
`['a'=>1]`, `'pre'.'fix'` count), `enclosingCallableOrProgram`.

## Performance — must stay O(N), not O(chains²)
Two rounds of measurement on real frameworks (isolated barrier-set probe, real-disk DBs, capped heap):

1. **Kill the pairwise relation.** The first cut defined `sameConstChain(a,b)` as a recursive BINARY relation;
   the optimizer materialised every matching PAIR of constant-key chains and re-ran `enclosingCallableOrProgram`
   (a `getParent+` closure) + `strictSubscriptKey` (a `concat`) inside that product — **>6.5 min, never
   converged, OOM on drupal (~10k files)**. Fix: FUNCTIONAL keys computed once per expression — `constChainKey(e)`
   (length-prefixed, collision-free string of root var + key sequence) and `constChainScope(e)` (innermost
   enclosing callable). "Same cell" = equal key AND equal scope, an equi-join, not a cartesian product.
2. **Precompute the guard sets, don't join per-candidate.** `cellPossiblyTainted` still walked every write/arg
   on a read's root, and `sameRootVarScope` was a second pairwise relation. Fix: precompute, ONCE, the guard
   sets keyed by `(constChainKey, constChainScope)` — `chainConstAssigned` / `chainTaintAssigned` /
   `chainPassedAsArg` — and by `(scope, name)` — `rootHasWildWrite`. Each candidate then does hash lookups on
   its ancestors' keys instead of a join. The highly-selective `provenConstWrittenRead` (a cell that has a
   constant-literal write) drives evaluation, so the taint-freedom check runs only for the few reads that can
   possibly be barriered.

Isolated-probe scaling, drupal (10k) / magento (25k), identical barrier sets (3366 / 402 cells) throughout:
`>390s→OOM  →  177s / 84s (functional keys)  →  24s / 42s (precomputed sets)`. Flat/sub-linear in file count.
As a dataflow `Sanitizer` the barrier can only PRUNE flow paths, so its only marginal cost over the base
engine is this one-time ~25-40s barrier-set computation — negligible against the fork's multi-minute
interprocedural dataflow. NOTE for benchmarking: build DBs on real disk (NOT tmpfs `/tmp`) and cap the JVM
heap (`-J-Xmx8g`) — CodeQL otherwise defaults `-Xmx` to ~70% of RAM, which with tmpfs DBs and leftover/
concurrent `codeql` JVMs OOM-kills the machine (an infra artifact, unrelated to barrier complexity; kill
stragglers by their java PID, not just the `sh` wrapper).

## Validation
- `scratchpad/arr` (FP + basic FN): `$d['table']`/nested `$e['sub']['table']` FPs suppressed; same-key
  (`$f['x']`), foreach, implode, nested same-key (`$i['sub']['x']`) all still fire.
- `scratchpad/arr2` (adversarial FN + recursion): dynamic-alias, same-key retaint, whole reassign, append,
  int-key tainted read all still FIRE (5/5); int-key const sibling, 3-LEVEL nested const sibling,
  augmented-sibling all suppressed (3/3).
- `cve/run.sh`: 201/201, 0 un-annotated.

## Adversarial validation (6 harnesses, ~40 cases)
`scratchpad/arr`..`arr6`, each cross-checked barrier-ON vs barrier-OFF to separate barrier-induced FNs from
pre-existing engine gaps. Confirmed SOUND (no barrier-induced FN) on: augmented `.=`/`+=` to the same cell,
nested same-cell taint, ancestor-tainted parent, dynamic sibling at a nested level, ternary/switch-branch
taint, cross-function scope gating, numeric-string vs int key equivalence, `$d += $_GET`, `array_merge`
reassign, `parse_str`/`sort`/user-by-ref whole-array mutation. Precision (correctly suppressed): int-key
const sibling, 3-level nested const sibling, augmented-on-sibling, const concat/arithmetic, both-branch-const.
Engine gaps found (NOT barrier FNs — don't fire even with the barrier off): taint through `list()`/array
DESTRUCTURING into an element, reverse reference-aliasing (`$r=&$c['k']; $r=$t`), single-element (not whole
array) passed by-ref.

## Residual (accepted, recall-first)
Flow-insensitive: if a key gets both a constant and a (dead/overwritten) tainted write, the flow is kept
(residual FP, never a FN). Passing the whole array to a read-only function still disables the barrier
(residual FP via the by-ref guard) — the sound trade to kill the `parse_str` FN class.
