# Plan d'amélioration — CodeQL-PHP

Plan complet issu de l'audit. Objectif : passer d'un « très bon prototype recall-first » à un
analyseur **défendable scientifiquement** (soundness sur le fragment statique de PHP, sur-approximation
explicite et bornée sur le dynamique).

## Principe directeur

> **Pousser la correction vers le bas.** ~80 % des steps hand-written de `defaultAdditionalTaintStep`
> sont des rustines qui compensent des fondations approximatives. On investit dans peu de fondations
> saines (types, post-update, CFG branchant) ; les steps disparaissent d'eux-mêmes.

Trois dettes structurelles dominent et se recoupent :
1. **Résolution par nom au lieu de par type** → `shared/typetracking` / inférence de type. *(entamé)*
2. **Absence de post-update** → mutations, by-ref, champs qui reviennent à l'appelant.
3. **Heuristiques lexicales « même fichier »** → à remplacer par SSA/scope + jumpStep propres.

Discipline : **chaque fix arrive avec un query-test** (cas vulnérable + cas safe) et ne doit pas
régresser la suite (actuellement 27 tests, DVWA 50/4).

---

## Légende

- Effort : S (≤ ½ j), M (1-3 j), L (semaine), XL (plusieurs semaines)
- Risque : L / M / H (probabilité de casser CFG/SSA/consistance ou d'exploser en perf)
- Statut : ☐ à faire · ◐ partiel · ☑ fait

---

## Phase 0 — Fondation type (FAIT)

| ID | Point | Fix livré | Statut |
|----|-------|-----------|--------|
| P0.1 | Résolution par nom (B2) | `TypeInference.qll` : `exprClass` (new/`$this`/params typés/SSA/retours typés) ; `viableCallable` dispatch par type + fallback nom | ☑ |

Prouvé : `query-tests/TypeDispatch` (bon dispatch + héritage), DVWA 50/4 préservé.

---

## Phase 1 — Fondations soundness (P0 restant)

| ID | Problème (audit) | Approche de fix | Fichiers | Effort | Risque | Tests | Dépend |
|----|------------------|-----------------|----------|--------|--------|-------|--------|
| 1.1 ◐ | `exprClass` incomplet | ☑ propriétés typées, `clone`, params typés, fluent `return $this`, retour typé, promotion (type ok). ☐ reste : docblocks `@var`, narrowing `instanceof` (dép. CFG) | `TypeInference.qll` | M | L | `query-tests/TypeSources` ✓ | P0.1 |
| 1.2 ◐ | **PostUpdate absent (B3)** | ☑ **flow-back de mutation setter** (`$o->set($t); use($o->f)`) via step type+scope-scopé (call-graph typé) — faux négatif corrigé, sans chirurgie moteur. ☐ reste : `PostUpdateNode` moteur complet (nœud `$this` synthétique), by-ref value-return, mutations de tableau | `TaintTrackingPrivate.qll` (step), `DataFlowPrivate.qll` (moteur, ☐) | L | H | `query-tests/SetterMutation` ✓ | P0.1 |
| 1.3 ◐ | Résolution nom → namespace (B2 reste) | ☑ `self::`/`static::`/`parent::`/`Class::` dispatch par type (`staticInferredMethod`, namespace-aware via `resolveClassReference`, RelativeScope géré) — `Safe::run` plus de FP cross-classe. ☐ reste : fallback fonctions par namespace, self:: dans code non-atteignable | `DataFlowPrivate.qll`, `TypeInference.qll` | M | M | `query-tests/StaticDispatch` ✓ | P0.1 |
| 1.4 ◐ | `__invoke`/`__construct` partiels (B8) | ☑ `new $c()` (instanciation dynamique, `$c` résout vers un nom de classe via SSA) → type inféré. ☐ reste : classes anonymes, `getInvokeCallee` via `exprClass` | `TypeInference.qll` | M | M | `query-tests/DynamicNew` ✓ | P0.1 |

**Sortie de phase** : le call-graph est typé + post-update opérationnel → on peut retirer les hacks
generator/by-ref (B7) et scoper `__toString` (B6, voir 2.4).

---

## Phase 2 — CFG branchant & précision

| ID | Problème | Approche | Fichiers | Effort | Risque | Tests | Dépend |
|----|----------|----------|----------|--------|--------|-------|--------|
| 2.1 ☑ | **CFG linéarisé (B5)** | **RÉSOLU pour `if`/`if-else`.** (1) CFG branchant : `IfTree` (fall-through, `StandardPreOrderTree`+`last` extra) pour `if`-sans-`else`, `IfElseTree` (`PostOrderTree`, route par `BooleanCompletion` via `isValidForSpecific`) pour `if/else` → vrais φ SSA. (2) **Clé que l'autre approche manquait** : le taint droppait au φ car `definitionValue(phi)` est vide → ajout de `definitionReachingValue` (suit les inputs du phi via `phiHasInputFromBlock`) dans `DataFlowPrivate` → le taint traverse le φ. ⚠️ helpers `ifHasElse` lisent l'AST BRUT (pas `rankedCfgChild`) sinon récursion non-monotone. Vérifié : `$y="safe";if($c){$y=t;}sink($y)` + if/else flaggés, branche non-teintée non-flaggée ; 44 tests verts, DVWA 50/4. **Reste** : boucles (back-edge φ), `while`/`for`. | `ControlFlowGraphImpl.qll`, `DataFlowPrivate.qll` | L | H | `query-tests/BranchTaint` ✓ | — |
| 2.2 | **SanitizerGuard mort (B4)** | Brancher les barrier-guards dans la config taint (`isBarrier`/guard-nodes) ; guards : `ctype_*`, `in_array($x,$allow)`, `preg_match`, `===`/`==` littéral, `is_numeric` | `Concepts.qll`, config des requêtes, `TaintTracking` | M | M | allow-list, `ctype_alnum`, bypass regex | 2.1 |
| 2.3 ◐ | Sinks trop larges (FP) | ☑ (c) condition du ternaire exclue du propagateur (branches seules, + elvis). ☐ (a) `argIndex -1` → indices précis ; (b) sinks typés par receveur | `TaintTrackingPrivate.qll` | M | L | `query-tests/Ternary` ✓ | P0.1 |
| 2.4 ☑ | `__toString` trop large (B6) | Scopé via `exprClass(obj)` hybride (précis si type inféré, fallback type-agnostique borné sinon) ; magic `__get`/`__call` généralisés de `resolvedNewClass`→`exprClass` | `TaintTrackingPrivate.qll` | S | L | `query-tests/ToStringScoped` ✓ | P0.1 |
| 2.5 | Writes conditionnels (B5 reste) | Une fois 2.1 en place, supprimer `inConditionalBranch`/certain=false ; la vraie phi du CFG gère les branches | `SsaImpl.qll` | S | M | if/else réassign | 2.1 |

---

## Phase 3 — Couverture (angles morts / FN)

| ID | Angle mort | Approche | Effort | Risque | Tests |
|----|-----------|----------|--------|--------|-------|
| 3.1 ☑ | Callables d'ordre supérieur | `array_map`/`usort`/`call_user_func`/… avec closure inline → l'argument data atteint le param de la closure (les 2 ordres d'args gérés) | L | M | `query-tests/HigherOrder` ✓ |
| 3.2 ◐ | `extract()`/`compact()`/`parse_str()` | ☑ `parse_str($t,$out)`/`mb_parse_str` → `$out` teinté (by-ref, scope-scopé). ☐ reste : `extract`/`compact` (risque FP) | `query-tests/ParseStr` ✓ |
| 3.3 ☑ | Références `&` | `$b =& $a` : assigner un alias teinte les reads de l'autre (bidirectionnel, même fichier) | M | M | `query-tests/RefsExceptions` ✓ |
| 3.4 ☑ | Exceptions | `throw new E($x)` … `catch($e){ $e->getMessage() }` → l'arg constructeur atteint les accessors de message | M | M | `query-tests/RefsExceptions` ✓ |
| 3.5 ☑ | Alias `use ... as` | `resolveClassReference` suit `use Qualified\Name as Alias` (même fichier) → le type d'une classe aliasée est résolu | S-M | L | `query-tests/UseAlias` ✓ |
| 3.6 ☑ | Named arguments PHP 8 | `f(cmd: $v)` : step nom→param + **fix moteur** (args nommés exclus du mapping positionnel de `getArgumentCfgNode` via `getName().(Php::Name)`) → recall + précision | S | L | `query-tests/NamedArgs` ✓ |
| 3.7 ☑ | `$GLOBALS['x']`, sessions | `$GLOBALS['k']=v` → reads de `$GLOBALS['k']` (même clé, cross-scope même fichier) | S-M | M | `query-tests/Globals` ✓ |
| 3.8 ☑ | Type juggling `==` | `Security/TypeJuggling.ql` (CWE-697) : `==`/`!=` sur hash/secret → bypass ; exclut `===`/`hash_equals` | S | L | `query-tests/TypeJuggling` ✓ |
| 3.9 | Second-order / stored | (Hors socle) config source-DB → sink-DB, ou marquer hors périmètre documenté | L | H | — |

---

## Phase 4 — Remplacer les hacks « même fichier » (B1)

À faire **après** que leurs fondations propres existent (dépendances explicites) :

| ID | Hack actuel | Remplacé par | Dépend |
|----|-------------|--------------|--------|
| 4.1 ◐ | `$this->f` même-fichier | ☑ this-field scopé par **classe** (`enclosingClassDecl`), by-ref scopé par **callable** (`sameScope`, top-level géré) — retire l'unsoundness cross-classe/cross-scope. Test `query-tests/FieldScoping`. ☐ reste : content model `TFieldContent(class,name)` + PostUpdate moteur | 1.2, 4.4 |
| 4.2 ☑ | `global $g` même-fichier | `jumpStep` propre (DataFlowPrivate) : `$g` = alias cross-scope value-preserving → **cross-fichier** (hack same-file retiré). Corrige B1 | `query-tests/GlobalsCrossFile` ✓ |
| 4.3 ☑ | capture closure/arrow, varvar même-fichier | capture arrow et varvar `$$n` scopées par `sameScope` (fini le cross-scope lexical) ; closure `use()` déjà scopée par corps | — |
| 4.4 | Field content global (perf) | Clé `TFieldContent` par (classe, nom) au lieu de nom global | 1.1 |

---

## Phase 5 — Performance & passage à l'échelle

| ID | Point | Approche | Effort |
|----|-------|----------|--------|
| 5.1 | `getParent+/*` dans ~7 steps | Précalculer `enclosingScope(node)` (relation cachée) et l'utiliser partout | M |
| 5.2 | Call-graph dense | Mitigé par P0.1 ; ajouter budget `MaxDepth`, mesurer sur repo réel (vendor/) | S |
| 5.3 ☑ | Pas de diagnostics | `Diagnostics/CallResolutionCoverage.ql` : % d'appels méthode/statique résolus par type vs fallback nom (métrique projet) | S |

---

## Phase 6 — Rigueur recherche (qualification)

| ID | Manque | Livrable | Effort |
|----|--------|----------|--------|
| 6.1 ☑ | Pas de vérité-terrain | Corpus labellisé = `semgrep-rules/php` (232 pos / 176 neg) ; métriques P/R mesurées dans `bench/PR_baseline.md` : **rappel 48% (113/232)**, évolution 18%→33%→48% sur la session, WordPress 100%. Harnais `bench/score_semgrep.py`. (☐ élargir à OWASP Benchmark + CVE réels) | M-L |
| 6.2 ◐ | Tests `--learn` = snapshot | ☑ Chaque query-test est conçu avec des cas **BUG vs safe** explicites, vérifiés (flag les bugs, pas les safe) — verdict de fait. ☐ formaliser en `@kind test` avec assertions | ongoing |
| 6.3 ☑ | Pas de bench perf | `bench/perf_bench.sh` : génère des projets synthétiques de tailles croissantes, mesure temps d'analyse vs LOC | S |
| 6.4 ☑ | Pas de threat model | `THREAT_MODEL.md` : périmètre, sound/sur-/sous-approximé, hypothèses sanitizers, reproductibilité | S |

---

## Graphe de dépendances (ordre conseillé)

```
P0.1 (types) ─┬─► 1.1 (exprClass étendu) ─► 2.4 (__toString scopé)
              ├─► 1.3 (namespace/static) 
              ├─► 1.4 (invoke/construct)
              └─► 2.3 (sinks typés)
1.2 (PostUpdate) ─► 4.1 (this-field) ─► (retrait hacks B1)
2.1 (CFG branchant) ─┬─► 2.2 (SanitizerGuard / bypass)
                     ├─► 2.5 (retrait uncertain-writes)
                     └─► 4.3 (capture/varvar)
Phase 3 (couverture) — largement indépendante, à intercaler
Phase 6 (métriques) — démarrer TÔT pour mesurer chaque phase (avant/après)
```

**Recommandation d'exécution** : 1.1 → 6.1 (baseline chiffrée) → 1.2 → 2.1 → 2.2 → 2.3/2.4 → Phase 3
au fil de l'eau → Phase 4 (nettoyage) → Phase 5. Mesurer P/R (6.1) **après chaque phase** pour prouver
le gain — c'est ce qui donne la valeur scientifique.

---

## Impact attendu (qualitatif)

| Phase | Gain principal |
|-------|----------------|
| 1 | Précision dispatch + mutations captées (moins de FP, moins de FN sur objets) |
| 2 | Détection de bypass de filtre/regex ; FP conditionnels supprimés |
| 3 | Couverture des vecteurs dynamiques (callbacks, extract, exceptions) |
| 4 | Suppression de l'unsoundness lexicale (cross-fichier correct) |
| 5 | Analyse d'un vrai repo Laravel + vendor à l'échelle |
| 6 | Chiffres P/R avant/après = argument de qualification |
