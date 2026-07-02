# CodeQL for PHP — Plan de construction

> Objectif : un support PHP **complet** pour CodeQL, de qualité comparable au support Ruby
> officiel (extractor + dbscheme + librairie QL + taint tracking global + modèles de frameworks
> + pack de requêtes de sécurité).

## 0. Principe directeur : ne pas réinventer le moteur

Le dépôt `github/codeql` est conçu pour ça. On **fork** et on ajoute un dossier `php/` qui
décalque `ruby/`. On réutilise TEL QUEL tout ce qui est dans `shared/` :

| Réutilisé (0 ligne à écrire) | Rôle |
|---|---|
| `shared/tree-sitter-extractor` (1624 LOC) | Parsing tree-sitter → TRAP, gestion fichiers, diagnostics |
| `shared/dataflow` (16 020 LOC) | **Le moteur de taint tracking interprocédural** |
| `shared/ssa` | Static Single Assignment (base du dataflow) |
| `shared/controlflow` | Construction générique de CFG |
| `shared/typetracking` | Suivi de types/valeurs pour le call graph |
| `shared/mad` | Models-as-Data (sources/sinks/summaries en YAML) |
| `shared/threat-models` | Regroupement des sources par modèle de menace |
| `shared/concepts`, `shared/regex`, `shared/namebinding` | Concepts partagés |

Ce qu'on écrit = uniquement la **couche spécifique PHP** : décrire au moteur ce qu'est un nœud
PHP, comment le flux y circule, et quels sont les sources/sinks du langage et des frameworks.

Le parser existe déjà : **`tree-sitter/tree-sitter-php`** (grammaire maintenue). On ne parse pas
PHP à la main.

---

## Phase 0 — Toolchain & scaffolding ✅ FAIT

- [x] Clone complet (shallow) `github/codeql` dans `codeql/`.
- [x] CodeQL CLI 2.25.6 installé dans `tools/codeql/`.
- [x] `tree-sitter-php` 0.24.2 ajouté comme dépendance Cargo (crates.io, pas de vendoring nécessaire).
- [x] Arborescence `php/` créée : `extractor/`, `ql/lib/`, `ql/src/`, `ql/test/`, `codeql-extractor.yml`, `tools/`.
- [x] Extractor ajouté au workspace Cargo (`Cargo.toml`) ; packs auto-découverts par `codeql-workspace.yml`.

**Livrable** : chaîne validée, squelette `php/` en place. Build via `php/build.sh`.

---

## Phase 1 — Extractor (PHP → base de données) ✅ FAIT

- [x] `generator.rs` : génère dbscheme (1842 l.) + AST QLL (`TreeSitter.qll`, 889 l.) depuis
      `tree_sitter_php::PHP_NODE_TYPES`.
- [x] `extractor.rs` : parse chaque fichier avec `LANGUAGE_PHP`, écrit le TRAP. Le HTML entrelacé
      et `<?php ?>` sont gérés **nativement par la grammaire** (pas de pré-scan type ERB).
- [x] `main.rs` + `autobuilder.rs` : sous-commandes Extract/Generate/Autobuild ; extensions
      `.php/.phtml/.inc/...`.
- [x] here/nowdoc, interpolation, short tags, `<?=` : couverts par tree-sitter-php.

**Livrable atteint** : `codeql database create --language=php` produit une base ; `import php`
compile ; requête structurelle valide.

**Test de validation (réussi)** :
```ql
import php
from Php::FunctionCallExpression call, Php::Name name
where name = call.getFunction()
select call, name.getValue()   // → system, eval, mysqli_query
```

---

## Phase 2 — Librairie AST (`codeql/php/ast`) ✅ FAIT (socle) — refinements optionnels restants

**But** : envelopper l'AST brut généré dans des classes QL ergonomiques (comme le fait Ruby avec
15 182 LOC de wrappers). C'est le plus gros bloc « écriture manuelle ».
Pattern : `class X extends AstNode instanceof Php::Y` (les classes générées sont `final`).

**FAIT — noyau hiérarchie de classes (testé, qltest vert)** :
- [x] `AstNode` (base : location, parent, file, primary QL class).
- [x] `Callable` / `Function` / `Method` / `Parameter` (+ `isStatic`/`isAbstract`).
- [x] `ClassLike` / `Class` / `Interface` / `Trait` / `Enum`.
- [x] **Héritage résolu** : `getASuperType`, `getAnImplementedInterface`, `getAUsedTrait`,
      `getAnAncestor` (transitif), `getATransitivelyUsedTrait`, `getAMethod`
      (déclarées + héritées + aplaties depuis les traits). MRO validé sur `Dog extends Pet
      implements Animal use Loggable`.
- [x] Harnais `qltest` opérationnel (`legacy_qltest_extraction: true` + `qltest.sh`).

**FAIT — résolution namespace + wrappers Expr/Stmt/Call (3 tests qltest verts)** :
- [x] Résolution **namespace-aware** : `getNamespace`/`getQualifiedName` + résolution des
      super-types/interfaces/traits par (nom simple + namespace). Désambiguïse deux `Base`
      homonymes dans deux namespaces (testé). Formes `namespace X;` et `namespace X { }`.
- [x] `Expr` : `VariableAccess`, `Literal`/`StringLiteral`, `BinaryOperation`/`ConcatExpr`/
      `ComparisonExpr` (avec `isStrict` pour `===`), `AssignExpr`, `ArrayAccess`, `CastExpr`.
- [x] `Call` : `FunctionCall`, `MethodCall` (+nullsafe), `StaticMethodCall`, `NewExpr`, arguments.
- [x] `Stmt` : `ExprStmt`, `EchoStmt`, `ReturnStmt`, `IfStmt`, `WhileStmt`, `ForeachStmt`.

**RESTE (refinements, non bloquants pour la suite)** :
- [ ] Résolution des alias d'`use`-imports (`use A\B\C; ... new C()`).
- [ ] Couverture exhaustive des nœuds restants (match, try/catch, closures détaillées…).
- [ ] Expressions : littéraux, variables, `ArrayExpr`, `BinaryOp` (dont `.`, `==` vs `===`),
      `UnaryOp`, `AssignExpr`, `TernaryExpr`, `NullCoalesce`, `MatchExpr`, interpolation.
- [ ] Appels : `FunctionCall`, `MethodCall`, `StaticMethodCall`, `NewExpr`, appels dynamiques
      (`$fn()`, `call_user_func`, `$obj->$m()`).
- [ ] Déclarations : `Function`, `Method`, `Class`, `Interface`, `Trait`, `Enum`, `Parameter`,
      `Property`, `ClassConst`, `Closure`, `ArrowFunction`.
- [ ] Statements : `If`, `While`, `For`, `Foreach`, `Switch`, `Try/Catch`, `Throw`, `Return`,
      `Echo`, `Global`, `Include/Require`.
- [ ] Résolution de noms (`shared/namebinding`) : namespaces, `use`, résolution de classe.

**Livrable** : lib AST navigable + tests unitaires (`ql/test/library-tests/ast`).

---

## Phase 3 — Control Flow Graph (`codeql/php/controlflow`) ✅ FAIT (v1 linéarisé)

Instancié via le module **`Make` sans splitting** de `shared/controlflow` (template : `actions`).

- [x] `InputSig` fourni : `Completion` (Simple/Boolean/Return), `CfgScope` (Program + Function/
      Method/Anonymous/Arrow), `getCfgScope`/`scopeFirst`/`scopeLast`.
- [x] `ControlFlowTree` : **tout nœud non-expression** (statements, `switch_block`, `case`,
      blocks, wrappers d'arguments…) en pré-ordre via `StructuralTree` ; expressions en
      **post-ordre** ; fonctions/closures/classes = feuilles avec leur propre scope. Garantit un
      graphe connecté à travers `switch`/nesting arbitraire (bug DVWA corrigé : le flux s'arrêtait
      au `switch`). ⚠️ ne pas mettre de garde dépendant de `ControlFlowTree` dans le charpred
      (recursion non-monotone) — exclure par type (`Php::Token`).
- [x] API publique : `CfgNode` (`getASuccessor`, `getScope`, `getAstNode`), `EntryNode`/`ExitNode`,
      `BasicBlock`. Câblé dans `php.qll`.
- [x] **Cohérence vérifiée** : `deadEnds`, `multipleToString`, `scopeNoFirst` tous vides.
      Test de régression `library-tests/cfg` (arêtes AST) vert. **4 tests qltest verts.**

**RESTE (raffinements)** :
- [ ] Branchement booléen (`if`/`while`/`match` → arêtes true/false) au lieu de la linéarisation.
- [ ] Court-circuit (`&&`/`||`/`?:`/`??`), complétions abnormales (`break`/`continue`/`return`/`throw`),
      `try/catch/finally`, `foreach` par référence, `goto`.
- [ ] Guards (conditions contrôlant un chemin) — nécessite le branchement booléen.

---

## Phase 4 — SSA & dataflow local (`codeql/php/dataflow`) ✅ FAIT (v1 def-use)

- [x] **`shared/ssa` instancié** (`dataflow/internal/SsaImpl.qll`) : `SourceVariable` = `$name`
      par CFG scope ; writes = LHS d'`=` ; reads = autres accès. Module `Cfg` implémentant
      `BB::CfgSig` + `Ssa::Make<Location, Cfg, SsaInput>`.
- [x] **`DataFlow::Node` + `localFlowStep`** (`dataflow/DataFlow.qll`) : step def-use — la RHS de
      `$v = rhs` flue vers chaque lecture de `$v` atteinte (via `ssaDefReachesRead`). `localFlow` =
      fermeture transitive.
- [x] Validé : `$_POST['cmd']` → `$cmd` dans `system($cmd)` (le cas invisible pour l'AST seule).
      Test de régression `library-tests/dataflow`. **5 tests qltest verts.**

**RESTE** :
- [ ] Writes de paramètres, `global`/`static`, `foreach`, augmented assignments, refs `&`.
- [ ] Instancier `shared/typetracking` pour un call graph approximatif (typage dynamique).
- [ ] Content/stores : tableaux (`$a['k']`), propriétés d'objet.
- [ ] Flux inter-procédural (argument→paramètre, retour→appel) — via le moteur global (Phase 5).

---

## Phase 5 — Taint tracking + sources/sinks ✅ FAIT (v1 — PoC ATTEINT)

Moteur de taint v1 (`dataflow/TaintTracking.qll`) construit sur le dataflow local (pas encore le
gros moteur global `shared/dataflow` — c'est le prochain gros chantier).

- [x] **Étapes de taint** : def-use local, concaténation, interpolation `"$x"`, array-read
      (`$_GET` → `$_GET['x']`), built-ins propagateurs (allowlist), cast `(string)`,
      **inter-procédural par nom** (argument→paramètre, return→appel).
- [x] **Sources** : superglobales `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/`$_FILES`/…
- [x] **Sinks** : command injection, code injection, SQLi, XSS, file inclusion, deserialization.
- [x] **Sanitizers** : `htmlspecialchars`/`intval`/… non propagés → le taint s'arrête (0 FP validé).
- [x] `hasTaintFlow(source, sink, kind)`.

**PoC ATTEINT** : sur un échantillon riche, **6 vraies injections détectées end-to-end, 0 faux
positif** (direct, def-use, concat, interpolation, inter-procédural, eval ; htmlspecialchars/intval
correctement ignorés). Test de régression `library-tests/taint`. **6 tests qltest verts.**

**FAIT — vrai moteur global `shared/dataflow` instancié + requêtes migrées** :
- [x] `codeql/php/{DataFlow,TaintTracking}.qll` + `dataflow/internal/*` (template actions).
      Interprocédural + field-sensitivity (content array/propriété) + `@kind path-problem`.
- [x] Les 10 requêtes CWE réécrites en **path-problem** dessus (`Flow::PathGraph`), helper
      `security/FlowSources.qll`. **Recall préservé (DVWA=44), chemins d'exploitation complets.**
- [x] Support field/getter/setter/magic, propriétés statiques, appels dynamiques `$fn()`.

**RESTE** :
- [ ] Migrer les `library-tests` sur le nouveau moteur, supprimer l'ancien (hand-rolled).
- [ ] Sources/sinks via **`shared/threat-models`** + **MAD** (YAML extensible).
- [ ] Guards type-juggling (`==` vs `===`), barrières (tuer les 3 FP DVWA restants).

---

## Phase 6 — Modèles de frameworks (le travail « sans fin »)

**But** : couvrir l'écosystème réel. Ruby y consacre ~16 000 LOC. Priorité par usage.

- [ ] **PDO / MySQLi / mysql_*** — sinks SQL + reconnaissance des requêtes préparées (sanitizer).
- [ ] **Laravel** — Eloquent, `Request`, `DB::raw`, Blade (XSS `{!! !!}`), routes.
- [ ] **Symfony** — `Request`, Doctrine DQL, Twig.
- [ ] **WordPress** — `$wpdb`, nonces, `esc_*`, hooks (énorme surface d'attaque réelle).
- [ ] **Guzzle / cURL** — SSRF.
- [ ] Templating : Twig, Blade, Smarty (contexte d'échappement auto).

**Livrable** : modèles versionnés + tests par framework.

---

## Phase 7 — Pack de requêtes de sécurité (`codeql/php/ql/src`)

Une requête `.ql` par CWE, avec métadonnées. Pack `codeql/php-queries` créé (`php/ql/src`).
FAIT (v1, `@kind problem`) : `CommandInjection.ql` (CWE-78), `SqlInjection.ql` (CWE-89),
`CodeInjection.ql` (CWE-94), `ReflectedXss.ql` (CWE-79). Validés via `codeql database analyze`
→ 6 alertes CSV/SARIF correctes. Passer à `@kind path-problem` quand le moteur global sera là.

- [x] SQL Injection (CWE-89)
- [x] Command Injection (CWE-78)
- [x] Code Injection / `eval` (CWE-94)
- [x] Reflected XSS (CWE-79)
- [ ] Path Traversal + LFI/RFI (CWE-22 / CWE-98) — spécifique PHP
- [ ] Unsafe Deserialization (CWE-502) — POP chains
- [ ] SSRF (CWE-918)
- [ ] Open Redirect, Header Injection (CWE-601 / CWE-113)
- [ ] Type Juggling / auth bypass `==` (spécifique PHP)
- [ ] XXE, LDAP/XPath injection, Regex DoS, Sensitive data / hardcoded creds.

**Livrable** : `codeql/php-queries` pack publiable.

---

## Phase 8 — Tests, QA, tuning faux-positifs

- [ ] Infra `qltest` (comme Ruby) : chaque lib + query a son test avec `.expected`.
- [ ] `consistency-queries` : invariants du dbscheme/CFG/dataflow.
- [x] **DVWA testé** (170 fichiers) : **17 alertes** (SQLi sqli/sqli_blind/bac/brute, cmd exec,
      XSS csp/reflected), **0 faux positif dans les `impossible.php`** (requêtes préparées PDO
      correctement ignorées). A révélé et fait corriger le bug CFG/switch.
- [ ] Benchmark plus large : bWAPP, CVE réels (WordPress plugin) → mesurer recall/precision chiffrés.
- [ ] Tuning des sanitizers/barriers pour réduire le bruit.

---

## Phase 9 — Packaging, CI, release

- [ ] CI (bazel + tests) sur le fork.
- [ ] Bundle CodeQL pack (extractor + libs + queries).
- [ ] Intégration `codeql database create --language=php`.
- [ ] Doc + change-notes + versioning dbscheme (upgrades/downgrades).
- [ ] (Optionnel) proposition upstream / publication comme pack communautaire.

---

## Difficultés spécifiques PHP & parades

| Problème | Parade |
|---|---|
| Typage dynamique → call graph flou | `shared/typetracking` + résolution conservatrice, sur-approximation |
| `$$x`, `extract()`, `${...}` | Modélisation conservatrice : toute variable variable = tainted-through possible |
| `include`/`require` dynamiques | Analyse par fichier + modèle de flux inter-fichiers best-effort |
| Type juggling (`0 == "abc"`) | Requête dédiée + traiter `==` comme non-sanitizer, seul `===` assainit |
| Méthodes magiques (`__get`, `__call`) | Steps de flux dédiés |
| Superglobales / état global | Sources modélisées globalement, pas de flux SSA classique |
| HTML entrelacé + templating | Contexte d'échappement (échappement auto Twig/Blade = sanitizer contextuel) |
| POP chains (deserialization) | Modéliser `__wakeup`/`__destruct` comme entrées de flux |

---

## Chemin critique / ordre d'exécution

```
Phase 0 ─► Phase 1 ─► Phase 2 ─► Phase 3 ─► Phase 4 ─► Phase 5 ─► Phase 7 (queries minimales)
                                                    └─► Phase 6 (frameworks, en parallèle continu)
Phase 8 (tests) accompagne chaque phase.  Phase 9 = release.
```

Un **PoC démontrable** = fin de Phase 5 (une vraie injection détectée end-to-end).
Un **produit crédible** = Phases 6-8 matures (c'est là que se joue le rapport signal/bruit).
