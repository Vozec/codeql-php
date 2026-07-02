# CodeQL-PHP — État du projet (handoff)

> **Fichier unique de synthèse.** Ce qui est fait, ce qui reste, le plan, l'architecture, et comment
> reprendre. Les documents de détail sont référencés en fin de page.

**Objectif du projet.** Un support **CodeQL pour PHP** de qualité comparable au support officiel
(Ruby/Python) : un fork de [`github/codeql`](https://github.com/github/codeql) ajoutant un pack de
langage `php/` complet — extracteur, AST, CFG, SSA, dataflow/taint interprocédural, modèles de
frameworks, et requêtes de sécurité. Priorité : **zéro angle mort** — aucun chemin d'exécution ni
branche de flux perdu à cause d'un cas non modélisé.

---

## Snapshot

| Métrique | Valeur |
|---|---|
| Pipeline | Extracteur Rust (tree-sitter-php) → TRAP → dbscheme → AST/CFG/SSA/DataFlow QL → requêtes |
| Requêtes de sécurité | **13** (Command/SQL/Code injection, XSS, Path traversal, Open redirect, SSRF, LDAP, File inclusion, Unsafe deser, Hardcoded crypto key, Type juggling) + 2 utilitaires (coverage, routes Laravel) |
| Modèles frameworks (MAD) | **7** — Laravel, Symfony, WordPress, PrestaShop, TYPO3, crypto, frameworks génériques |
| Tests | **45 tests verts** (30 query-tests + 15 library-tests) — baseline CLI 2.25.6, cf. `AUDIT.md` §7 |
| Banc de validation | **DVWA : 50 findings taint + 17 type-juggling, 6 dans `impossible.php`** (tolérés/documentés) |
| Extracteur | ~250 LOC Rust (réutilise `shared/tree-sitter-extractor`) |

---

## Architecture (pipeline CodeQL)

```
  6. Requêtes .ql (php/ql/src) + suites + tests            ← alertes SARIF/CSV
  5. DataFlow / taint interprocédural (php/ql/lib/.../dataflow)
       ├─ sources/sinks/sanitizers : Concepts + MAD (ext/*.model.yml) + FlowSources
       ├─ steps taint génériques (TaintTrackingPrivate) + phi-input flow (DataFlowPrivate)
       └─ moteur global shared/dataflow (field-sensitivity, chemins, contextes)
  4. Graphe d'appels — dispatch PAR TYPE (TypeInference.qll) + fallback par nom
  3. SSA + dataflow local (SsaImpl) — def-use, φ aux joins
  2. CFG (ControlFlowGraphImpl) — pré-ordre stmts, post-ordre expr, BRANCHES if/if-else
  1. Extracteur / AST (extractor Rust + ast/*.qll + TreeSitter.qll généré)
```

**Décision d'architecture clé** : réutiliser **tel quel** tout `shared/` (dataflow 16k LOC, ssa,
controlflow, tree-sitter-extractor) — langage-agnostique — et n'écrire que la couche QL spécifique PHP.

---

## Ce qui est FAIT

### Fondations moteur (le socle « pas de cas-par-cas »)

- **Inférence de type & dispatch par type** (`TypeInference.qll`) — `exprClass` résout la classe d'un
  receveur depuis `new C()`, `$this`, paramètres typés, SSA, retours déclarés, `return $this` fluent,
  propriétés typées + promues, `clone`, `new $c()` dynamique. `viableCallable` fait le dispatch **par
  type** avec fallback **par nom** (recall-first). → `$safe->run()` n'est plus un faux positif.
- **CFG branchant `if` / `if-else`** ✅ (l'item le plus dur) — vrais **φ SSA** aux joins :
  - `IfTree` : `if` sans `else`, la condition est un `last` supplémentaire (fall-through).
  - `IfElseTree` : `if/else`, la condition route par `BooleanCompletion` (vrai/faux) vers then/else qui
    rejoignent — **pas de fuite `then → else`**.
  - **`definitionReachingValue`** (`DataFlowPrivate`) : la pièce clé — suit les inputs d'un φ
    (`phiHasInputFromBlock`) pour que **le taint traverse le join** (sans ça, le taint droppe au φ).
  - Vérifié : `$y="safe"; if($c){$y=$_GET['x'];} sink($y)` et le cas `if/else` sont flaggés ; la
    branche non-teintée seule ne l'est pas.
- **Dispatch statique** `self::`/`static::`/`parent::`/`Class::` par type, namespace-aware.
- **Instanciation dynamique** `new $c()`, **magic methods** toutes (`__get`/`__set`/`__call`/
  `__callStatic`/`__invoke`/`__toString`/`__wakeup`/`__destruct`), **flow-back de setter**.

### Couverture de flux (angles morts fermés)

Callables d'ordre supérieur (`array_map`/`usort`/`call_user_func`), `parse_str` by-ref, références
`&`, exceptions (`throw new E($x)` → `$e->getMessage()`), alias `use … as`, **named args** (+ fix
moteur du mapping positionnel), `$GLOBALS` cross-scope, **globals cross-fichier** (`jumpStep`),
type juggling `==` (CWE-697), ternaire scopé, built-ins propagateurs.

### Frameworks (Models-as-Data, **sans modif moteur**)

Laravel, Symfony, WordPress, PrestaShop, TYPO3 — sources/sinks/steps/sanitizers en `ext/*.model.yml`,
community-extensibles.

### Retrait des hacks lexicaux « même fichier » (soundness)

`this`-field scopé par classe, by-ref/varvar/capture-arrow scopés par `sameScope` (plus de faux liens
cross-scope), global via `jumpStep` moteur propre.

---

## Ce qui RESTE (par ordre recommandé)

Détail complet, avec pour chaque item *test qui échoue → fix général → non-régression*, dans
**`STRUCTURAL_ROADMAP.md`**.

### Phase A — compléter les chemins de contrôle (P0)
> Détail + bugs de soundness associés dans **`AUDIT.md` Phase A** (source de vérité désormais).
- **Boucles `while`/`do`** — ✅ **FAIT** (`WhileTree`/`DoTree`, back-edge, test `LoopTaint` vert).
- **Boucles `for`/`foreach`** — back-edge `corps → tête` pour le φ de boucle (reste à faire).
- **`switch`/`match`** — arêtes de cas (et pas de fall-through pour `match`).
- **Court-circuit `&&` `||` `??`** — arêtes booléennes.
- **Complétions anormales** `break`/`continue`/`return`/`throw → catch`.
- **Bug strong-update** `$a[k]=v` tue toute la racine (`AUDIT.md` A.1) ; `$x .= …` LHS non lu (A.2).
- **Retrait du hack SSA** *uncertain-writes* une fois les vraies branches partout (gated, `AUDIT.md` A.7).

### Phase B — précision
- **SanitizerGuard** (2.2) — `if (ctype_alnum($id)) query($id)` : barrer `$id` sur l'arête vraie
  (dépend des `BooleanCompletion` du CFG branchant).

### Phase C — complétude du flux
- **PostUpdateNode moteur** (1.2) — nœud `$this`/argument « après l'appel » pour les mutations.
- **Content par classe** (4.4) — clé `(classe, champ)` au lieu du nom global ; éléments de tableau.
- **Dispatch : angles morts** — traits injectés, héritage transitif, first-class callable méthode,
  late static binding.

### Phase D — dette & rigueur
- **Migrer sources/sinks/sanitizers hardcodés → DATA** (`ext/*.model.yml`) — finir le patch unitaire
  hérité de `FlowSources.qll` ; le moteur ne garde que la *logique*, plus les *noms*.
- **Corpus labellisé + Précision/Recall** (6.1) — livrable de recherche : ground truth + P/R par CWE,
  mesuré avant/après chaque item ci-dessus.
- **Perf** — précompute des scopes, bornes d'exploration.

---

## Build & exécution

Voir **`DEV.md`** pour les commandes reproductibles. En résumé :

```bash
# Construire l'extracteur + le pack
codeql/php/build.sh

# Créer une base et analyser
codeql database create <db> --language=php --source-root=<src> --search-path=codeql/php
codeql database analyze <db> codeql/php/ql/src/codeql-suites/php-security.qls \
    --format=csv --output=results.csv --search-path=codeql/php --additional-packs=codeql

# Tests
codeql test run codeql/php/ql/test --search-path=codeql/php --additional-packs=codeql
```

**Pièges connus** (détaillés dans `DEV.md`) : `--search-path` =
`codeql/php` ; `.dbscheme.stats` requis (`codeql dataset measure`) ; artefacts `*.testproj` périmés →
faire avorter la suite (nettoyer avant un run complet).

---

## Principes de qualité (non négociables)

1. **Recall d'abord**, soundness sur le fragment statique, sur-approximation **bornée et documentée**
   sur le dynamique (voir `THREAT_MODEL.md`). Un cas non modélisé sur-approxime (FP potentiel), il ne
   **coupe jamais** un chemin (pas de FN silencieux).
2. **Pas de patch unitaire.** La couverture (quelles fonctions sont dangereuses) est de la **DATA**
   (MAD) ; le moteur (dispatch, propagation, mutations, CFG) est **principiel/général**.
3. **Chaque fix arrive avec un test** (cas vulnérable + cas safe) et ne régresse pas la suite.

---

## Documents de référence

| Fichier | Contenu |
|---|---|
| **`STRUCTURAL_ROADMAP.md`** | Feuille de route détaillée par étape du pipeline (le « reste à faire ») |
| **`IMPROVEMENTS.md`** | Plan d'amélioration issu de l'audit (~30 items, statuts ☑/◐/☐) |
| **`THREAT_MODEL.md`** | Périmètre de soundness, sur-approximations assumées |
| **`DEV.md`** | Build, commandes reproductibles, pièges |
| **`PLAN.md`** | Plan initial en 9 phases (historique) |
| **`bench/`** | Scripts de benchmark (perf, scoring semgrep) |
