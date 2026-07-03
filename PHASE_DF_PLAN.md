# Plan détaillé — Phases D (AST public) & F (Bazel)

> Branche `phase-d-f-hardening`. Exécution autonome, test-first, un commit par étape vérifiable.
> Filet : `.tooling/codeql/codeql test run php/ql/test` doit rester vert à chaque étape D.

## ✅ ÉTAT — LES DEUX PHASES SONT FAITES (branche `phase-d-f-hardening`, suite 72/72)
- **Phase D ✅** : D.1 (signature `resolveClassReference` → `AstNode`), D.2 (wrappers publics
  include/shell/throw/clone/print/array/closure + switch/try/for/do/catch/break/continue), D.3 (API
  publique `dataflow/CallGraph`, migration LaravelRoutes + CallResolutionCoverage hors `internal`),
  D.4 (imports `use` non-aliasés), D.5 (cleanup toString). Seul SemgrepAudit (bench) garde `internal`.
- **Phase F Bazel ✅** : `php/{,extractor/,ql/lib/,tools/}BUILD.bazel` + `php/scripts/create-extractor-pack.sh`
  (calqués ruby) ; `tree-sitter-php` enregistré dans le vendoring cargo Bazel (régénéré, Cargo.lock **minimal**
  sans bump des autres langages) + MODULE.bazel. **Vérifié** : `bazel build //php/extractor:extractor` →
  *Build completed successfully*.

---
### Plan d'origine (référence) :

## Phase D — Hiérarchie AST publique (rendre `Php::*` privé du point de vue des requêtes)

**Constat** : `Php::*` (types générés tree-sitter) est défini dans `ast/internal/TreeSitter.qll`. Les
wrappers publics (`Expr`, `VariableAccess`, `BinaryOperation`, `FieldAccess`, …) existent déjà mais
partiellement ; certaines **signatures publiques** exposent encore `Php::` (le vrai leak), et il manque
des wrappers pour des nœuds courants (les requêtes utilitaires doivent alors importer `internal`).

**Principe** : `Php::` est autorisé dans les **corps** de wrappers et les modules `internal/` (couche
d'implémentation). Il est **interdit** dans (a) une signature de prédicat/classe **publique**, (b) une
requête `src/`. Objectif = aucune requête n'a besoin d'`import …ast.internal.TreeSitter`.

### Étapes (chacune : édition → `codeql test run` vert → commit)
- **D.1** Fixer la seule signature publique fuyante : `resolveClassReference(Php::AstNode)` → prendre un
  wrapper public. Ajouter un wrapper `NameRef`/`TypeRef` (nom simple + namespace) ; overloader/rendre le
  helper interne. Vérifier les appelants (TypeInference interne : OK, il peut passer le nœud).
- **D.2** Compléter les wrappers de nœuds **sécurité-critiques** manquants et les exposer publiquement :
  `IncludeExpr`/`RequireExpr(_Once)`, `ShellCommandExpr` (backtick), `EvalExpr`, `IncludeOnce`,
  `ThrowExpr`, `Unary`/`UpdateExpr`, `Clone`, `Print`, `ArrayLiteral`+`ArrayElement`+`Pair`,
  `MatchExpr`+arms, `TryStmt`/`CatchClause`/`FinallyClause`, `SwitchStmt`/`CaseStmt`, `ForeachStmt`,
  `Attribute*`. Chaque wrapper : `class X extends AstNode/Expr/Stmt instanceof Php::X` + accesseurs
  publics ; `Php::` reste dans le corps.
- **D.3** Migrer les 3 requêtes utilitaires hors `internal` en s'appuyant sur les wrappers D.2 :
  `Routing/LaravelRoutes.ql` (string value, closures, array), `Diagnostics/CallResolutionCoverage.ql`
  (exposer `MethodCall.getInferredTarget()` / `hasResolvedTarget()` en API publique au lieu de
  `TI::hasInferredReceiver`). `SemgrepAudit.ql` = helper de bench → soit le migrer, soit le sortir du pack.
- **D.4** Résolution de noms principielle : calculer le **FQN** d'une déclaration une fois (namespace
  courant), construire une **table d'imports `use` par fichier** (alias + tail-of-path, groupes,
  non-aliasés), résoudre les refs contre elle uniformément — remplacer le match par dernier-segment
  (`simpleNameOf`) et gérer `use App\Foo; … Foo` (non-aliasé, actuellement manquant). Test dédié.
- **D.5** Nettoyage : `override string toString()` redondants (`Expr.qll`, `Stmt.qll`) ; en-tête `php.qll`
  périmé ; `getDeclaringType()` typé `ClassLike` au lieu de `AstNode`.

## Phase F — Bazel (build CI/release de l'extracteur)

**Constat** : le build **Cargo** marche déjà (workspace, vérifié). Bazel est le build upstream. Il faut :
1. **MODULE.bazel** : ajouter l'entrée `vendor_ts__tree-sitter-php-<ver>` (à côté de la ruby, l.158) dans
   `use_repo(...)` de l'extension tree-sitter-extractors.
2. **Vendoring 3rdparty** : `misc/bazel/3rdparty/tree_sitter_extractors_deps/` doit contenir
   `BUILD.tree-sitter-php-<ver>.bazel` (calqué sur `BUILD.tree-sitter-ruby-0.23.1.bazel`) et l'enregistrer
   dans `defs.bzl` (`aliases()`, `all_crate_deps()`). **Généré** par
   `bazel run //misc/bazel/3rdparty:vendor_tree_sitter_extractors` — lit le `Cargo.toml` du workspace (qui
   inclut déjà `php/extractor` + `tree-sitter-php`), donc le crate est pris automatiquement.
3. **`php/extractor/BUILD.bazel`** : calqué sur `ruby/extractor/BUILD.bazel` (`codeql_rust_binary` +
   `all_crate_deps`).
4. **`php/BUILD.bazel`** : calqué sur `ruby/BUILD.bazel` (pack dbscheme + extractor-pack).
5. **`php/scripts/create-extractor-pack.sh`** : calqué sur ruby (remplace le `build.sh` maison).

**Contrainte environnement** : `bazel`/`bazelisk` non installés ici, et la régénération du vendoring est un
gros téléchargement réseau non vérifiable sans la toolchain. Stratégie autonome :
- (a) Installer `bazelisk` (télécharge bazel 9.0.0 via `.bazelversion`).
- (b) Ajouter l'entrée MODULE.bazel + le dep tree-sitter-php (déjà dans Cargo.toml workspace).
- (c) `bazel run …:vendor_tree_sitter_extractors` pour générer `BUILD.tree-sitter-php-*.bazel` + `defs.bzl`.
- (d) Créer `php/extractor/BUILD.bazel`, `php/BUILD.bazel`, `create-extractor-pack.sh` (mirrors ruby).
- (e) `bazel build //php/...` pour vérifier.
- Si (a)/(c)/(e) échouent (réseau/toolchain), livrer les fichiers Bazel **mirrorés à la main** (étapes b/d)
  et le `BUILD.tree-sitter-php` calqué, en documentant qu'un `bazel run vendor` régénère/valide — plutôt
  que de committer un état non-buildable dans la branche principale.

## Ordre d'exécution
D d'abord (verifiable, haute valeur), puis F. D est découpé D.1→D.5, chacun test-vert + commit. F selon la
faisabilité de la toolchain, commité seulement si buildable (ou clairement marqué WIP sur la branche).
