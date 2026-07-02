# PHP CodeQL — état de dev & commandes reproductibles

## État actuel : Phase 0 + Phase 1 ✅ (pipeline complet fonctionnel)

- Extractor Rust construit (`codeql/php/extractor/`, réutilise `shared/tree-sitter-extractor` + `tree-sitter-php` 0.24.2).
- dbscheme (1842 l.) + lib AST générée (`TreeSitter.qll`, 889 l.) depuis la grammaire tree-sitter.
- `codeql database create --language=php` fonctionne.
- `import php` compile ; requêtes structurelles OK (appels `system`/`eval`/`mysqli_query` détectés).

## Layout

```
codeql/                      # fork github/codeql (shallow), workspace Cargo + QL
  php/
    extractor/src/           # main.rs, extractor.rs, generator.rs, autobuilder.rs
    codeql-extractor.yml     # déclare l'extracteur "php"
    php.dbscheme             # copie à la racine du pack (requis par le CLI pour l'import TRAP)
    build.sh                 # build reproductible
    tools/linux64/extractor  # binaire packagé
    tools/*.sh               # index-files.sh, autobuild.sh, qltest.sh
    ql/lib/
      qlpack.yml             # codeql/php-all (library)
      php.qll                # import de tête
      php.dbscheme(.stats)
      codeql/Locations.qll, codeql/files/FileSystem.qll   # copiés de ruby (génériques)
      codeql/php/ast/internal/TreeSitter.qll              # AST généré
tools/codeql/                # CodeQL CLI 2.25.6 (binaire)
```

## Toolchain

- Racine projet : `/home/vozec/Desktop/dev/codeql-php` (l'ancien `Desktop/r&d/PHPcodeQl` n'existe plus).
- CodeQL CLI : **non vendorée dans le repo** — l'obtenir séparément depuis
  [`github/codeql-cli-binaries`](https://github.com/github/codeql-cli-binaries) (match du pack : 2.25.x+),
  la mettre sur le `PATH` ou pointer `CODEQL=/chemin/vers/codeql/codeql`.
  (Copie locale de dev : `.tooling/codeql/codeql`, 2.25.6, git-ignorée.)
- Rust pin repo : 1.88 (via `rust-toolchain.toml`, installé par rustup).

## Commandes clés

```bash
REPO=/home/vozec/Desktop/dev/codeql-php
CODEQL="$REPO/.tooling/codeql/codeql"   # ou tout `codeql` sur le PATH
```

Build complet de l'extracteur + lib :
```bash
bash "$REPO/php/build.sh"
```

Créer une base depuis des sources PHP (search-path = dossier de l'extracteur `php/`) :
```bash
"$CODEQL" database create /path/to/db --language=php \
  --source-root=/path/to/php-src --search-path="$REPO/php"
```

Générer les stats (après tout changement de schéma) :
```bash
"$CODEQL" dataset measure --output "$REPO/php/ql/lib/php.dbscheme.stats" /path/to/db/db-php
```

Lancer une requête :
```bash
"$CODEQL" query run query.ql --database=/path/to/db --additional-packs="$REPO"
# où query.ql commence par:  import php
```

Lancer la suite de tests (baseline : 45 verts — 30 query + 15 library) :
```bash
"$CODEQL" test run "$REPO/php/ql/test" --search-path="$REPO/php" --additional-packs="$REPO"
# --learn pour (re)générer les .expected ; toujours relire un .expected généré (une erreur de
# compilation s'y écrit aussi et passerait pour de la donnée).
```

## Pièges résolus (Phase 1)

1. **Notification background prématurée** sur `cargo build` → toujours vérifier la présence du binaire.
2. **unzip du CLI** échoue (Zip64) → utiliser `bsdtar -xf`.
3. **`--search-path`** doit pointer sur le dossier de l'extracteur (`$REPO/php`), pas le parent.
4. **dbscheme** doit être copié à la racine du pack (`php/php.dbscheme`) pour l'import TRAP.
5. **`.dbscheme.stats`** requis à la compilation → généré via `dataset measure`.

## Phase 2 — lib AST ergonomique ✅ (socle complet, testé)

Fichiers dans `php/ql/lib/codeql/php/` :
- `AST.qll` (agrégateur : AstNode, Callable, Class, Expr, Call, Stmt), importé par `php.qll`.
- `ast/AstNode.qll`, `Callable.qll`, `Class.qll`, `Expr.qll`, `Call.qll`, `Stmt.qll`.
- `ast/internal/Naming.qll` (simpleNameOf), `ast/internal/Namespace.qll` (namespace-aware).
- Pattern obligatoire : `class X extends AstNode instanceof Php::Y` (classes générées `final`).
  Désambiguïser les prédicats hérités des deux supertypes par cast : `this.(Php::Y).m()`.
- Résolution de types : `resolveClassReference(refNode)` matche (nom simple + namespace).
  `use`-import aliases PAS encore suivis (refinement noté).

### Tests (qltest) — 3 verts
- `php/ql/test/qlpack.yml` + `library-tests/{inheritance,namespaces,calls}/`.
- `legacy_qltest_extraction: true` requis dans `codeql-extractor.yml` (+ `tools/qltest.sh`).
- Lancer : `codeql test run php/ql/test/library-tests --search-path="$REPO/php" --additional-packs="$REPO"`
  (`--learn` pour (re)générer les `.expected`).
- ⚠️ `--learn` écrit AUSSI les erreurs de compilation dans le `.expected` → toujours relire le
  `.expected` généré pour vérifier que ce sont de vraies données, pas un message d'erreur.

## Phase 3 — CFG ✅ (v1 linéarisé, testé)

Fichiers `php/ql/lib/codeql/php/controlflow/` :
- `internal/ControlFlowGraphImpl.qll` : instanciation `CfgShared::Make<Location, Implementation>`
  (module **sans splitting**). Completion (Simple/Boolean/Return), CfgScope (Program + callables),
  trees (Program/Statement pré-ordre, Expr post-ordre, Arguments/Argument traversés, scope
  boundaries = feuilles).
- `ControlFlowGraph.qll` : `CfgNode`/`EntryNode`/`ExitNode`/`CfgScope` publics.
- `BasicBlocks.qll` : `BasicBlock`.
- Câblé dans `php.qll`. Dépendance `codeql/controlflow` ajoutée au qlpack.

Template de référence : `actions/ql/lib/codeql/actions/controlflow/internal/Cfg.qll` (le plus compact).
⚠️ `toString` : NE PAS redéfinir sur les wrappers `instanceof` (classes sœurs co-enveloppant un
nœud → `multipleToString`). Un seul `toString` (base AstNode = getPrimaryQlClass).

Vérifier la cohérence CFG : query sur `Impl::CfgImpl::Consistency::{deadEnd,multipleToString,scopeNoFirst}`
(chemin complet `codeql.php.controlflow.internal.ControlFlowGraphImpl`).

## Phase 4 — SSA + dataflow local ✅ (v1 def-use, testé)

Fichiers `php/ql/lib/codeql/php/dataflow/` :
- `internal/SsaImpl.qll` : module `Cfg` (implémente `BB::CfgSig<Location>` en réexposant
  `CfgImpl::CfgImpl::{Node,BasicBlocks::BasicBlock,EntryBasicBlock,dominatingEdge}`), `LocalVariable`
  (newtype (scope,name)), `SsaInput` (variableWrite=LHS d'`=`, variableRead=reste),
  `Ssa::Make<Location, Cfg, SsaInput> as Impl`.
- `DataFlow.qll` : `module DataFlow` avec `Node` (=Expr), `localFlowStep` (def-use via
  `Impl::ssaDefReachesRead`), `localFlow` (fermeture transitive).
- Dépendance `codeql/ssa` ajoutée au qlpack. Câblé dans `php.qll`.

Validé : `$_POST[..]` → `$cmd` dans `system($cmd)`. Test `library-tests/dataflow`.
Note : flux à travers concat (`$id` → `"...".$id`) = étape TAINT (Phase 5), pas dataflow pur.

## Phase 5 — Taint tracking ✅ (v1, PoC atteint, testé)

Fichiers :
- `php/ql/lib/codeql/php/dataflow/TaintTracking.qll` : `module TaintTracking` — `isSource`
  (superglobales), `isSink(node, kind)` (cmd/code/SQL/XSS/file/deser), `taintStep` (def-use +
  concat + interp + array-read + built-ins propagateurs + cast string + inter-procédural par nom),
  `hasTaintFlow(source, sink, kind)`. Sanitizers = fonctions non listées dans propagatingBuiltin →
  le taint s'arrête naturellement (htmlspecialchars/intval).
- `php/ql/src/qlpack.yml` (`codeql/php-queries`) + `Security/{CommandInjection,SqlInjection,
  ReflectedXss,CodeInjection}.ql` (`@kind problem`).

Usage SAST réel :
```bash
codeql database analyze <db> "$REPO/php/ql/src/Security" --format=csv --output=r.csv \
  --search-path="$REPO/php" --additional-packs="$REPO"
```
Validé : 6 vraies injections, 0 FP. Test `library-tests/taint`. 6 tests qltest verts.

## Complétude "zéro angle mort" (moteur durci)

Méthodo = audit piloté données : `php/ql/consistency-queries/CfgConsistency.ql` liste tout
Statement/Expression runtime NON couvert par le CFG. **Résultat : 0 gap sur tout PHP valide**
(DVWA 170 fichiers, corpus syntaxe exhaustive, corpus liaisons). Lancer :
`codeql query run php/ql/consistency-queries/CfgConsistency.ql --database=<db> --additional-packs="$REPO"`.

Couvert désormais : `switch`/`case` (StructuralTree = tout nœud non-expression), **paramètres +
valeurs par défaut** (CallableTree), toutes formes de liaison SSA (`=`,`.=`,`=&`, params, foreach
`$v`/`$k=>$v`/`[$a,$b]`, list/`[...]` destructuring nested, `global`, `static`, `catch`).
Exclus (corrects, non-runtime) : contenus d'attributs `#[...]`, initialiseurs constants
(property/const/enum-case defaults), noms de types, EmptyStatement.
Parse errors → diagnostic `broken.php:1: A parse error occurred...` (shared extractor). **Toujours
`php -l` un fichier de test avant de conclure à un bug moteur.**

Limitations connues (documentées) : global-aliasing cross-scope, closure `use(...)` capture,
guards/barriers (validation) → sur-approx recall-first, moteur global field-sensitive (futur).

## Vrai moteur shared/dataflow (fondation, séparé) + PHP dynamique

- **Vrai moteur instancié** : `codeql/php/DataFlow.qll`, `codeql/php/TaintTracking.qll`,
  `dataflow/internal/{DataFlowPublic,DataFlowPrivate,DataFlowImplSpecific,TaintTrackingPrivate,
  TaintTrackingImplSpecific}.qll`. Template = `actions`. Interprocédural PROUVÉ (DataFlow::Global /
  TaintTracking::Global). PAS encore câblé dans les requêtes (l'ancien moteur reste actif). Reste :
  PostUpdateNode (field-sensitivity `$a[k]=v`), source implicit-read, migration requêtes en path-problem.
- **Moteur actif (recall-first) couvre maintenant** : `$var[$x]`, propriétés, getters/setters/magic
  (`__get`/`__call` via receveur teinté), propriétés statiques `C::$p`, appels dynamiques
  `$fn()` (résolution string via SSA), call_user_func. Field-INSENSITIVE (sur-approx voulue).
- **Limitations documentées** : `$$name`→variable normale, callee=élément tableau, closure `use()`,
  goto, global-aliasing. 10 tests qltest verts, DVWA=44 (3 FP guard-limités).

### Prochaine étape : le "mieux du mieux"
Remplacer le reachability fait-main par le **vrai moteur global `shared/dataflow`** (field-sensitivity,
`@kind path-problem` avec chemins, contextes d'appel), + sources/sinks via `shared/threat-models` +
MAD (YAML). Puis Phase 6 (frameworks Laravel/Symfony/WordPress) et Phase 8 (benchmark DVWA/CVE).
