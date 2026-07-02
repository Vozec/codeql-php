# AUDIT — Inventaire complet du pack `php/`

> **But** : fork propre, fonctionnel, mergeable un jour dans `github/codeql`.
> Zéro bricolage, zéro cas-par-cas : la sémantique PHP est modélisée au plus bas niveau
> (extractor/AST/CFG/SSA/dataflow), la couverture (noms de fonctions dangereuses) est de la DATA (MAD).
>
> **Reprise après crash** : ce fichier est le journal d'audit + le plan de remédiation.
> Chaque item du plan (§P) a un ID, un statut (`☐ TODO` / `◐ WIP` / `☑ DONE`) et se commit séparément.
> Historique : `git log --oneline -- AUDIT.md`. État du code : `git log --oneline -5`.
>
> Audit réalisé le **2026-07-02** par 6 agents parallèles (read-only) comparant chaque couche aux
> conventions upstream de `ruby/`. CLI utilisé : CodeQL 2.25.6 (dans `.tooling/`, git-ignoré).

---

## VERDICT GLOBAL : **non-mergeable en l'état** — socle sain, finition « recherche »

Le squelette (réutilisation de `shared/` : tree-sitter-extractor, controlflow, ssa, dataflow) est
**idiomatique et propre**. `TypeInference.qll` est réellement principiel. Mais 3 familles de problèmes
bloquent le merge **et** violent la règle « pas de cas-par-cas » :

1. **Bricolage de soundness dans CFG/SSA** — un hack `uncertain-writes` qui casse les strong-updates
   (→ FP), des mises à jour d'élément qui tuent la variable entière (→ FN), et ~8 constructions de
   contrôle linéarisées (for/foreach/switch/match/court-circuit/try-catch/complétions anormales).
2. **Cas-par-cas hardcodé en QL** — sources/sinks/sanitizers/steps des builtins PHP écrits en listes
   de chaînes dans `.qll` au lieu d'être de la DATA (MAD). Trois pièces moteur (`PostUpdateNode`,
   `lambda*`, `SanitizerGuard`) stubbées à `none()` et rustinées par des taint-steps par-pattern.
3. **Hygiène de packaging/merge** — binaire extractor committé, `php/` absent du workspace Cargo &
   Bazel, aucun `.qhelp`, suites non-standard, MAD sans colonne `provenance`, 5 requêtes important des
   modules `internal`, docs-diary + README écrasé à la racine.

**Aucun problème n'est dans la plomberie des libs partagées** — tout est dans les choix de modélisation
et l'emballage. C'est réparable proprement, mais c'est un chantier structurel, pas du polish.

### Tableau de gravité (compte des findings)

| Axe | BLOQUANT-MERGE | HACK | INCOMPLET | DOC-PÉRIMÉE |
|---|---|---|---|---|
| 1. Extractor + packaging | 4 | 3 | 2 | 3 |
| 2. AST | 3 | 3 | 3 | 4 |
| 3. CFG + SSA | 3 | 2 | 4 | 3 |
| 4. DataFlow / Taint / TypeInf | 4 | 4 | 4 | 2 |
| 5. Requêtes + tests + MAD | 4 | — | 3 | 2 |
| 6. Docs / hygiène | 5 | — | 2 | 6 |

---

## §1 — Extractor Rust + packaging  (verdict : Rust propre, packaging non-mergeable)

**Positifs** : `main/extractor/generator/autobuilder.rs` calquent ruby et réutilisent
`shared/tree-sitter-extractor` sans réimplémenter. Aucun chemin machine hardcodé dans `php/`. dbscheme
réellement **généré** (`generator.rs`, en-tête « do not edit ») → pas de risque de maintien manuel.
`php.dbscheme.stats` réel (598 Ko). qlpacks auto-découverts par `codeql-workspace.yml`.

**BLOQUANT-MERGE**
- `php/tools/linux64/extractor` — **binaire ELF 6.5 Mo committé** (`git ls-files` le suit). Upstream ne
  commit jamais d'extracteur buildé. → supprimer du git, `.gitignore`, produire par le build.
- `Cargo.toml:5-16` — `php/extractor` **absent des `members`** du workspace ; `Cargo.lock` n'a aucune
  entrée `codeql-extractor-php`/`tree-sitter-php`. `php/build.sh:11` (`cargo build -p …`) ne résout pas
  depuis la racine. → ajouter `"php/extractor"` aux members, régénérer `Cargo.lock`.
- **Aucun câblage Bazel** : pas de `php/BUILD.bazel` ni `php/extractor/BUILD.bazel` ; `tree-sitter-php`
  non enregistré dans le vendoring cargo Bazel. Tous les langages upstream buildent via Bazel. → ajouter
  les cibles + le crate.
- `php/codeql-extractor.yml:37` — TRAP compression `^(none|gzip|brotli)$` alors que le shared ne
  supporte que `none|gzip|zstd`. `brotli` est inparsable, `zstd` inatteignable. → aligner sur l'enum.

**HACK / INCOMPLET**
- `php/build.sh` + absence de `php/scripts/create-extractor-pack.sh` — script de build maison au lieu du
  flux standard `create-extractor-pack.sh` + Bazel. → remplacer.
- `php/php.dbscheme` (racine) **duplique** `php/ql/lib/php.dbscheme` (ruby ne commit que celui du pack).
  → cesser de committer la copie racine, la générer au build.
- Overlay à moitié câblé : `extractor.rs:75,135,163` lisent les env `_OVERLAY_*` mais `codeql-extractor.yml`
  n'a pas `overlay_support_version` ni `qlpack.yml: compileForOverlayEval` → code mort. → câbler ou retirer.
- `php/analyze.sh` — wrapper hors-pack sans analogue ruby. → sortir du pack.

**STYLE** : `Cargo.toml authors=["PHPcodeQl"]` (ruby `["GitHub"]`) ; `[[bin]]` explicite superflu ;
`tools/index-files.sh`/`autobuild.sh` sans shebang ni `set -eu`.

---

## §2 — Couche AST  (verdict : non-mergeable — API fuit les types générés, couverture partielle)

**Positifs** : `Locations.qll`/`FileSystem.qll` sont **byte-identiques** à ruby (génériques propres, pas
hackés). `AstNode` fournit un `getParent()`/`getAChild()` normalisé (les enfants tree-sitter bruts ne
fuitent pas à la base). **Aucun nom de classe/fonction hardcodé** dans la couche AST (correct).

**BLOQUANT-MERGE**
- `Class.qll:132` `resolveClassReference(Php::AstNode)` — prédicat **public** prenant un type généré
  `Php::AstNode` en signature → fuite du type interne dans l'API publiée. Idem `getAUsedTrait`
  (`Class.qll:88`). → n'exposer que des wrappers publics ; `Php::*` strictement privé.
- **Pas de hiérarchie publique synthétisée** — chaque wrapper est `extends AstNode instanceof Php::X` ;
  tout cast consommateur tombe sur `Php::*`. Ruby n'expose jamais les types générés. → adopter le pattern
  ruby (`Generated::*` interne + classes publiques synthétisées).
- **Couverture incomplète (nœuds sécurité-critiques manquants)** : `Include/Require(_Once)` (LFI/RFI),
  `ShellCommandExpression` (backtick RCE), `Eval/Exit`, `MemberAccess`/`ScopedPropertyAccess`/
  `ClassConstantAccess`, `Property/Const/EnumCase` declarations, attributs PHP8, `ArrayCreation/Pair/
  ListLiteral`, `For/Do/Switch/Case/Try/Catch/Finally/Throw/Break/Continue/Match`, ternaire,
  unaires/update/augmented, `Clone/Yield/Print`, `Heredoc/Nowdoc`, use-clause de closure, `use` top-level.
  → wrapper systématique table-driven contre `TreeSitter.qll`.

**HACK**
- `Naming.qll:12 simpleNameOf` — résolution par **dernier segment de nom** (string-match) ; confond deux
  classes de même nom court. → nom pleinement qualifié calculé une fois.
- `Class.qll:136-142` — `use`-alias : ne gère que les alias (`use X as Y`), via `toString()` d'un nœud,
  et **même fichier seulement** ; les imports non-aliasés (`use App\Foo;` puis `Foo`), groupes, relatifs,
  `\`-global non gérés. → table d'imports par fichier, résolution uniforme.
- `Callable.qll:57 getDeclaringType()` retourne `AstNode` via `getParent().getParent()` positionnel
  (devrait être `ClassLike`) ; idem accès positionnels `Expr.qll:81-84`, `Call.qll:26`.

**INCOMPLET** : closures sans classes exposant les captures ; `Method` sans visibilité/final/type de
retour ; `Class` sans `getConstant/getProperty/getEnumCase` ; `Namespace.qll:67` sans relatifs/`\`.

**DOC/STYLE** : `php.qll:6` en-tête « Phase 1 raw AST » périmé (CFG/dataflow importés) ; `toString()`
overrides redondants (`Expr.qll:8`, `Stmt.qll:9`).

---

## §3 — CFG + SSA  (verdict : NON-mergeable — vrais bugs de soundness, pas juste incomplétude)

**Positifs** : usage **idiomatique** du shared `codeql.controlflow.Cfg` (Completion/CfgScope/`Make<>`,
PostOrder/StandardPreOrder/Leaf trees) et du shared `codeql.ssa.Ssa` via `InputSig`. La plomberie est
propre — l'unsoundness est entièrement dans les choix de modélisation.

**BLOQUANT-MERGE**
- `SsaImpl.qll:155-177` — **hack uncertain-writes détruit les strong-updates**. `inConditionalBranch ⇒
  certain=false` marque *tout* write en branche comme may-write : il ne tue jamais un def antérieur. Dans
  une même branche `if($c){ $y=$_GET['x']; $y="safe"; sink($y); }`, la 2e écriture (sanitisante) est
  uncertain → le taint survit → **FP**, indépendant de tout join. Ruby n'utilise `certain=false` que pour
  de vrais may-writes (captures). → tous les writes syntaxiques `certain=true` ; s'appuyer sur les vrais φ.
- `ControlFlowGraphImpl.qll:230-243` (StructuralTree) — **branchement massivement manquant** : `for`,
  `foreach`, `switch`/`case`/`default`, `match`, court-circuit `&& || ??`, `break`/`continue`/`return`/
  `throw`, `try`/`catch`/`finally` — tous présents dans l'AST mais **linéarisés**. Conséquences : pas de
  back-edge for/foreach (taint de boucle uniquement via le hack) ; pas d'isolation de case (write case-N
  → read case-M = FP) ; pas d'arête throw→catch (param de catch inatteignable = FN) ; code après
  `return`/`throw` traité comme vivant (FP code-mort). → Trees branchants par construction, calqués ruby.
- `SsaImpl.qll:70-91,116-118` — **`$a[k]=v` / `$o->p=v` = strong-update tuant la racine**.
  `updateBaseVariable` fait un write **certain** de tout `$a`, tuant son def antérieur. Donc
  `$a=$_GET; $a['x']='safe'; sink($a['y']);` **perd le taint** → **FN/unsound**. Une mutation partielle
  doit être un weak-write (uncertain) ou read+partial-def, jamais un kill.

**HACK**
- `SsaImpl.qll:168-177 inConditionalBranch` — special-casing par ancêtre AST (node-type case-by-case),
  découplé de la structure CFG réelle. **Redondant** pour if/while/do (φ via `definitionReachingValue`) →
  double-modélisation, provenance ambiguë, chemins dupliqués. Retrait : supprimer le prédicat, tous les
  writes `certain=true`. **Risque de régression** : switch/match/for/foreach reposent *uniquement* sur ce
  hack aujourd'hui → le retrait doit être **gated** sur l'atterrissage de leurs Trees branchants.
- `DataFlowPrivate.qll:309-315 definitionReachingValue` — marche φ-input récursive ; correcte en soi, mais
  empilée sur le hack = 2e moitié du double-modèle.

**INCOMPLET**
- `ControlFlowGraphImpl.qll:23,78-82` — `ReturnCompletion`/`TReturnCompletion` **jamais produits** (code
  mort) ; `return` non modélisé comme complétion anormale.
- `CfgConsistency.ql` n'assure que « chaque Stmt/Expr a *un* CfgNode » → **passe malgré l'absence d'arêtes
  de branche** : fausse assurance, ne détecte aucun des trous ci-dessus.
- `SsaImpl.qll:179-186` — LHS d'un augmented-assign (`$x .= …`) écrit mais **pas lu** → taint de
  l'ancienne valeur perdu = FN.
- Tests CFG minces : `cfg/flow.php` = une fonction linéaire ; **aucun test négatif** pour le FP
  strong-update du hack, aucun pour switch/match/for/foreach/try.

**DOC-PÉRIMÉE** : `ControlFlowGraphImpl.qll:244-252` — NOTE mensongère (« if branching disproven /
linéarisé ») contredite 30 lignes plus bas par `IfTree`/`IfElseTree`. En-têtes `:9-10` / `SsaImpl:8-9`
listent params/foreach/global/static comme « not yet modelled » alors qu'ils sont implémentés.

---

## §4 — DataFlow / TaintTracking / TypeInference  (verdict : non-mergeable — cas-par-cas hardcodé)

**Positifs (à garder)** : `TypeInference.qll` **principiel** (new/`$this`/params typés/SSA/retours
typés/fluent `return $this`/props typées/`clone`/dynamique `new $c`), récursif avec fallback par nom.
`simpleLocalFlowStep` via SSA + fix φ (`:309-315`) correct et général. `structuralPropagator`
(`TaintTrackingPrivate:462-481`) = le bon pattern « énumérer une fois, composer récursivement » — le
modèle de ce que les listes hardcodées devraient devenir.

**BLOQUANT-MERGE (le cœur du « pas de cas-par-cas »)**
- `security/FlowSources.qll:11-221` — **tous les builtins cœur hardcodés en QL, pas en MAD** :
  `isRemoteSource` (superglobales + `getenv`/`filter_input` + liste de noms de méthodes), `isSanitizerFunction:54-73`
  (~35 noms), `sinkFunctionKind:86-113` (chaque builtin dangereux→kind), listes `call_user_func`/`array_map`.
  Le MAD existe déjà (`ModelExtensions.qll` + `ext/*.yml` ne portent que le framework). → livrer
  `ext/php-builtins.model.yml`, supprimer les listes QL ; le moteur ne garde que le glue générique. **Plus gros blocker.**
- `TaintTrackingPrivate.qll:107-117 propagatingBuiltin` + `:409` (HO-callbacks) + `:425` (parse_str) +
  `:399` (accesseurs d'exception) — **couverture taint cuite dans le `.qll`**. `strtoupper/trim/substr…`
  = `stepModel` ; `array_map/usort/call_user_func`, `parse_str` = summaries. → tous les *noms* en `.model.yml`.
- `Concepts.qll:54 SanitizerGuard` = **code mort** (référencé nulle part ; les requêtes n'utilisent que
  `isBarrier = n instanceof Sanitizer`). Sanitisation par branche (`if(ctype_alnum($x))`, `in_array`,
  `===`) non modélisée. → câbler guard→barrier (over-approx OK) ou retirer la classe + sa doc.

**HACK (patches par-pattern tenant lieu de pièces moteur → FN silencieux)**
- `DataFlowPrivate.qll:220-224 PostUpdateNode = none()` — mutation-après-appel non modélisée. Papier
  par des taint-steps étroits : setter (`:335-356`), by-ref `&$r` (`:236-254`, **fonctions seulement, pas
  méthodes**), `parse_str` (`:425`). Tout pattern de mutation non énuméré = **FN**. → implémenter
  `PostUpdateNode`/`getPreUpdateNode` sur receveurs + `&`-args, laisser le moteur porter le flux inverse.
- `DataFlowPrivate.qll:410-418 lambda* = none()` — flux d'ordre supérieur via le moteur absent ; seules
  les closures *inline* passées à une liste de builtins hardcodée marchent. Callback stocké en var / passé
  à une fonction user qui l'appelle = **FN**. → `lambdaCreation`/`lambdaCall` généraux.
- **Named-args = taint-only + fonctions seulement**. `getArgumentCfgNode:79-83` retire correctement les
  named args du mapping positionnel, mais le step de reconnexion (`:437-450`) ne matche que
  `FunctionCall→FunctionDefinition`. Named args vers méthodes/statique + tout le flux **pure-DataFlow** =
  FN. → mapper named→positional dans la couche arg/`parameterMatch` pour tous les types d'appel.
- `viableCallable:170-173` — **coupe le fallback par nom dès qu'un type de receveur est inféré**, même si
  la classe n'a pas la méthode (`__call`, sous-classe sous-approximée). → `getTypedCallee` vide **et**
  fallback bloqué = arête perdue = **FN**. Sur-précision violant recall-first. → gater le fallback sur
  « un callee typé a réellement été trouvé », pas sur « le type existe ».

**INCOMPLET / précision**
- `TFieldContent(name)` **clé par nom global** (`:240-242,355-379`) → confond `$a->id` et `$b->id` en
  interprocédural. → approx par `(classe, champ)` quand le type est inféré.
- `$GLOBALS['k']` et alias `=&` restreints **même fichier** (`:358-385`) → cross-file = FN. → jump-steps
  par nom/clé.
- `CastNode = none()` ; flux ctor-arg → propriété promue absent (`new C($t)` puis `$o->f`) = FN.

**DOC-PÉRIMÉE** : `Concepts.qll:50-57` documente `SanitizerGuard` comme point d'extension vivant (inerte) ;
`FlowSources.qll:223,231,240` prétend « extensible via data » alors que le set autoritatif est le QL hardcodé.

---

## §5 — Requêtes + tests + MAD  (verdict : non-mergeable — qhelp/suites/MAD)

**Positifs** : les 10 requêtes taint cœur (Command/Sql/Code injection, XSS, Path, OpenRedirect, SSRF,
LDAP, FileInclusion, UnsafeDeser) sont uniformes, métadonnées correctes (`@id php/…`, `@kind path-problem`,
`@security-severity`, tags CWE), et **sourcent les sinks depuis `Sink.getKind()` + MAD, pas de hardcode
dans le `.ql`**. Tests = **vraies données path-graph** (edges/nodes/#select), cas safe présents et
correctement exclus. Prédicats extensibles `ext/*.yml` ↔ `ModelExtensions.qll` cohérents, pas de ligne malformée.

**BLOQUANT-MERGE**
- **Les 15 requêtes sans `.qhelp`** (`find` → aucun). Upstream rejette toute requête sécurité sans qhelp.
  → un `<Query>.qhelp` par requête (overview/recommendation/example/references).
- **Suites : seul `php-security.qls`, format non-standard** (hand-code `include: kind/tags`, `queries: .`).
  Manque `php-code-scanning.qls`, `php-security-extended.qls`, `php-security-and-quality.qls`. Le
  code-scanning ne les trouvera pas. → suites standard via `suite-helpers`.
- **MAD = réimplémentation privée, pas le shared MaD**. `ModelExtensions.qll:19-36` déclare des
  `sourceModel(3col)/sinkModel(4col)/…` maison **sans colonne `provenance`, sans `neutralModel`/`typeModel`,
  sans `ModelValidation`** → n'interopère pas avec l'outillage MaD upstream. → migrer vers les extensibles
  `codeql/dataflow` standard (colonnes type/path/kind/**provenance**) + ModelValidation.
- **5 requêtes src importent `internal`** : `SemgrepAudit`, `LaravelRoutes`, `TypeJuggling`,
  `HardcodedCryptoKey`, `CallResolutionCoverage` importent `…ast.internal.TreeSitter` / `…internal.TypeInference`.
  Violation de couche interdite upstream. → exposer les classes nécessaires en API publique.

**INCOMPLET**
- **ReflectedXss rate `print()`** : `ReflectedXss/test.php:3` annoté `// BUG` (`print($_POST['x'])`) mais
  absent du `.expected` (seul le `echo` ligne 2 y est). **Trou de couverture masqué par un test vert.**
  → ajouter `print` comme sink XSS, MAJ expected.
- `SemgrepAudit.ql` émet des **lignes dupliquées** (un nom → plusieurs ruleIds) ; `@precision low`, sans
  `@security-severity`, très bruyant. → dédupliquer.
- `TypeJuggling`/`SemgrepAudit`/`LaravelRoutes` **hardcodent des noms en QL** (listes hash/banned/verbes). → MAD.

**STYLE** : `frameworks.model.yml:1-13` en-tête parle d'un `summaryModel` inexistant (le vrai est
`stepModel`) ; `whereRaw` dupliqué (`frameworks:41`, `laravel:36`) ; source `HardcodedCryptoKey` en
string-shape TreeSitter inline plutôt qu'un Concept réutilisable.

---

## §6 — Docs / hygiène de merge  (verdict : docs périmées & contradictoires, à relocaliser)

**BLOQUANT-MERGE**
- `DEV.md:32,40,45,46` — **tous les chemins pointent vers `/home/vozec/Desktop/r&d/PHPcodeQl/…`
  (n'existe plus)**. Un agent frais échoue ligne 1. → réécrire avec la vraie racine + note « obtenir le
  CLI séparément ».
- **7 `.md` diary à la racine** (`PROJECT_STATUS`, `STRUCTURAL_ROADMAP`, `IMPROVEMENTS`, `THREAT_MODEL`,
  `PLAN`, `AUDIT`, `DEV`) — racine upstream n'a rien de tel. → déplacer sous `php/docs/` ; **exclure
  `AUDIT.md` du merge**.
- **`README.md` racine écrasé** par un README de pack PHP → clobbe le README du monorepo. → `php/README.md`,
  restaurer le README racine dans la branche de merge.
- **`bench/`** (perf/scoring semgrep) = scratch recherche. → sous `php/` ou hors branche de merge.
- **Aucune change-note `php`** — les autres packs livrent `<lang>/ql/{lib,src}/change-notes/`. → ajouter.

**DOC-PÉRIMÉE (claims faux vs code)**
- **Compte de tests** : docs disent « 43 (30+15) » ; réel = **45** (30 query + 15 library ; 30+15≠43).
  `IMPROVEMENTS` dit 27 puis 44. **4 chiffres différents ; vérité = 45.**
- while/do « à finir » (`PROJECT_STATUS:92`) alors qu'implémentés + `LoopTaint.expected` vert.
- NOTE `ControlFlowGraphImpl.qll:244-252` (déjà en §3).
- **DVWA incohérent** : 50 / 44 / 17 selon les docs ; FP 6 / 3 / 4. Invérifiable ici, docs se contredisent.
- `DEV.md` = phase-log figé en Phase 5 (« dataflow pas encore câblé », « frameworks futurs ») alors que
  tout est présenté comme livré ailleurs.
- « 13 requêtes sécurité » : 13 `.ql` dans `Security/` mais un est `SemgrepAudit` (helper), la liste en
  nomme 12. Réel : **12 sécurité + 3 utilitaires**.

Vérifiés **corrects** : Rust 251 LOC ✓, 7 MAD ✓.

---

# §P — PLAN DE REMÉDIATION (exécution item par item, un commit chacun)

> Ordre = dépendances techniques d'abord (CFG avant retrait du hack), puis dette DATA, puis hygiène.
> **Règle** : chaque item = *test qui échoue (rouge) → fix général → suite verte → commit*. Jamais de
> patch cas-par-cas. Statuts : ☐ TODO · ◐ WIP · ☑ DONE.

## Phase 0 — Vérité de base & filet (rapide, non-risqué)  — ☑ FAIT (45/45 verts, sans warning)
- `P0.1` ☑ DEV.md réparé (chemins réels + note CLI + commande de test) ; compteurs corrigés (tests=45)
  dans PROJECT_STATUS/README/IMPROVEMENTS ; while/do marqués faits ; piège `r&d`-quoting retiré.
- `P0.2` ☑ NOTE mensongère `ControlFlowGraphImpl.qll:244-252` supprimée ; en-têtes CFG & SsaImpl
  réécrits pour refléter le réel.
- `P0.3` ☑ Baseline consigné (§7) : `All 45 tests passed` (CLI 2.25.6).
- `P0.4` ☑ `CfgConsistency.ql` durci : nouvel invariant `linearisedBranch` (toute construction qui *doit*
  brancher mais dont aucun nœud n'a ≥2 successeurs est signalée). Compile ✓ ; suite 45/45 (non-régressif).
- `P0.5` ☑ Warning cast redondant `TaintTrackingPrivate.qll:349` supprimé.

## Phase A — CFG complet & correct (débloque le retrait du hack ; cœur soundness)
> Méthode test-first, un Tree branchant par construction, calqué sur ruby.
- `A.1` ☑ **Bug strong-update élément/propriété** — `$a[k]=v` / `$o->p=v` sont désormais des **weak
  writes** (`SsaImpl.variableWrite`: `isPartialUpdate → certain=false`) et `definitionReachingValue`
  (`DataFlowPrivate`) suit `uncertainWriteDefinitionInput` pour que le def antérieur (teinté) traverse.
  Test `PartialUpdate` (3 BUG + 1 safe). **Conséquence assumée** : avec `$GLOBALS` field-insensitive, un
  write constant sur une clé ne peut plus strong-kill le taint d'une autre clé → 1 FP toléré
  (`Globals` ligne 6, annoté ; correctif précis = content par `(var,clé)`, item B.6). Suite 47/47.
- `A.2` ☑ **augmented-assign lu** (`$x .= …`) — LHS marqué **read** (ancienne valeur, read-before-write) +
  write ; valeur du def = l'expr augmentée ; `AugmentedAssignmentExpression` ajouté au `structuralPropagator`
  (taint des 2 opérandes). Test `AugmentedAssign` (ligne 8 = le FN corrigé, + ligne 13, safe ligne 18). Suite 47/47.
- `A.3` ☑ `for` / `foreach` — `ForTree`/`ForeachTree` (PostOrderTree) avec vrais back-edges : `for` =
  init→cond→body→update→cond (φ à la condition, condition du `for` ajoutée aux `BooleanCompletion`) ;
  `foreach` = collection→header(binding)→body→header (φ au binding). Discriminant testé = taint
  **loop-carried** (use-before-assign dans le corps, FN sur CFG linéarisé). Tests `ForLoopTaint`/`ForeachTaint`.
- `A.5` ☑ **Court-circuit `&& || ??`** — `LogicalAndTree`/`LogicalOrTree`/`NullCoalesceTree` (PostOrderTree).
  `&&`/`and` : gauche vrai→droite, faux→résultat ; `||`/`or` : gauche faux→droite, vrai→résultat (BooleanCompletion
  sur l'opérande gauche) ; `??` : branche non-déterministe (pas de nullness completion). Exclus du `ExprTree`.
  Taint via opérandes inchangé (`structuralPropagator`). Test `CfgShortCircuit` (expected vide = tout branche).
- `A.4a` ☑ **`match`** — `MatchTree` (subject→bras non-déterministe→résultat, exclu de `ExprTree` ;
  `MatchBlock` exclu de `StructuralTree` pour ne pas linéariser les bras) + **taint-step** retour de bras →
  résultat (le vrai FN : le résultat ne portait aucun taint). Test `MatchTaint` (retours teintés flaggés,
  subject teinté seul = safe).
- `A.4b` ☐ **`switch` + `break`** — ⚠️ **à co-livrer avec A.6** : sans `break`, le fall-through de `switch`
  relie tous les cases (fuite inter-case) — l'isolation n'a de sens qu'avec la complétion `break`.
  Tests : fall-through explicite (BUG) vs case isolé par `break` (safe).
- `A.6` ☐ Complétions anormales `break`/`continue`/`return`/`throw`→`catch`, `try/catch/finally` ;
  produire réellement `ReturnCompletion` (code mort actuel). Tests : catch-param taint (FN), code-mort (FP).
  **`break`/`continue` à co-livrer avec `switch` et à re-vérifier sur les boucles A.3 (sortie/continuation).**
- `A.7` ☐ **Retirer le hack uncertain-writes** (`SsaImpl.qll:155-177`) : `isPartialUpdate` reste uncertain
  (A.1), mais retirer `inConditionalBranch` (tous les autres writes `certain=true`). **Gated sur A.4–A.6**
  (déjà OK pour if/while/do/for/foreach). Test rouge du FP intra-branche (`$y=t;$y="safe";sink($y)` — cf.
  §3 BLOQUANT). Re-valider toute la suite.

> **État Phase A (checkpoint)** : A.1 ☑ A.2 ☑ A.3 ☑ ; reste A.5 (propre, next), A.4+A.6 (entrelacés), A.7 (final).

## Phase B — Moteur dataflow complet (retire les patches par-pattern)
- `B.1` ☐ `PostUpdateNode`/`getPreUpdateNode` généraux (receveurs + `&`-args, méthodes incluses) →
  retirer les taint-steps setter/by-ref/parse_str par-pattern.
- `B.2` ☐ `lambdaCreation`/`lambdaCall` (closures, `__invoke`, first-class callables) → retirer la liste
  HO hardcodée.
- `B.3` ☐ Named-args mappés named→positional dans la couche arg (tous types d'appel, dataflow+taint).
- `B.4` ☐ `viableCallable` : fallback gated sur « callee typé trouvé », pas sur « type existe ».
- `B.5` ☐ `SanitizerGuard` : câbler guard→barrier (BooleanCompletion du CFG A) **ou** retirer proprement.
- `B.6` ☐ Content par `(classe, champ)` quand type inféré ; `$GLOBALS`/`=&` cross-file en jump-steps.

## Phase C — Migration DATA (le « pas de cas-par-cas », gros bloc)
- `C.1` ☐ `ext/php-builtins.model.yml` : migrer sources/sinks/sanitizers/steps de `FlowSources.qll` &
  `TaintTrackingPrivate.qll` vers MAD. Moteur = glue générique seul.
- `C.2` ☐ Migrer les listes QL des requêtes (`TypeJuggling`/`SemgrepAudit`/`LaravelRoutes`) vers MAD.
- `C.3` ☐ MAD au format shared upstream (colonne `provenance`, `typeModel`/`neutralModel`, `ModelValidation`).

## Phase D — AST propre & complet (mergeabilité API)
- `D.1` ☐ `Php::*` strictement privé ; wrappers publics ; retirer les fuites de type des signatures.
- `D.2` ☐ Compléter les wrappers de nœuds manquants (include/require, shell, match, try/catch, attributs…).
- `D.3` ☐ Résolution de noms principielle (FQN calculé une fois ; table d'imports par fichier).

## Phase E — Requêtes mergeable
- `E.1` ☐ Un `.qhelp` par requête.
- `E.2` ☐ Suites standard (`code-scanning`/`security-extended`/`security-and-quality`) via suite-helpers.
- `E.3` ☐ Retirer les imports `internal` des 5 requêtes (exposer en public).
- `E.4` ☐ Fix `ReflectedXss` (sink `print`), dédup `SemgrepAudit`.

## Phase F — Packaging & hygiène merge (dernier, une fois le code stable)
- `F.1` ☐ `php/extractor` dans le workspace Cargo + `Cargo.lock` régénéré.
- `F.2` ☐ Cibles Bazel `php/BUILD.bazel` + `php/extractor/BUILD.bazel` + crate `tree-sitter-php`.
- `F.3` ☐ Décommiter le binaire extractor + dbscheme racine ; `create-extractor-pack.sh` standard.
- `F.4` ☐ Fix `codeql-extractor.yml` TRAP (`none|gzip|zstd`) ; overlay câblé ou retiré.
- `F.5` ☐ Relocaliser les docs sous `php/docs/`, restaurer README racine, sortir `bench/` & `AUDIT.md` de
  la branche merge ; ajouter change-notes `php`.

---

## §7 — Run de la suite de tests (baseline)

> CLI CodeQL **2.25.6** dans `.tooling/codeql/codeql` (git-ignoré). Commande :
> `.tooling/codeql/codeql test run php/ql/test --search-path=php --additional-packs=.`

**Baseline (2026-07-02, CLI 2.25.6) : `All 45 tests passed.`** — 30 query-tests + 15 library-tests,
5m28s (extract 1m6s / comp 4m5s / eval 12.9s). Confirme que le vrai compte est **45** (docs disaient 43).
C'est la référence de non-régression : tout item du plan doit finir sur `45/45` (ou +N nouveaux tests verts).

**Warning de compilation à nettoyer** (P0.5) : `TaintTrackingPrivate.qll:349` — `test is always true, as
VariableAccess is a supertype…` (cast redondant `recv instanceof VariableAccess`, `recv` déjà typé).

**Rappel** : la suite verte ne prouve PAS l'absence de bugs — l'audit a trouvé des trous masqués *par
omission dans les `.expected`* (ReflectedXss `print` = FN réel, pourtant « vert »). Les items du plan
ajoutent les tests rouges manquants avant de corriger.
