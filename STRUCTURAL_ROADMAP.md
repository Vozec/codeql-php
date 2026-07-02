# Feuille de route structurelle — CodeQL PHP

> **Objectif** : une chaîne d'analyse **saine et complète**, où *aucun chemin d'exécution ni aucune branche de flux de données n'est perdu à cause d'un cas non modélisé*. Pas de patch unitaire (ajouter un nom de fonction à une liste) : chaque item ci-dessous corrige une **étape du pipeline** de façon générale, pour que tout le PHP soit couvert par construction.
>
> **Principe directeur** : *recall d'abord, soundness sur le fragment statique, sur-approximation bornée et documentée sur le dynamique*. Un chemin non modélisé doit provoquer une **sur-approximation** (on garde le flux, quitte à un FP), jamais une **coupure silencieuse** (perte de vrai positif).

## Comment lire ce document

Le pipeline CodeQL se lit de bas en haut. Un défaut à une étape basse **plafonne** tout ce qui est au-dessus :

```
  6. Requêtes (.ql) + suites + tests/métriques
  5. Dataflow / taint interprocédural     ← sources/sinks/steps/barriers
  4. Graphe d'appels (dispatch)           ← quelle fonction est appelée
  3. SSA + dataflow local                 ← def-use dans une fonction
  2. CFG (control-flow graph)             ← quels chemins existent   ⟵ FONDATION
  1. Extracteur / AST (tree-sitter-php)   ← quels nœuds existent
```

Chaque section : **État** · **Où on perd un chemin** · **Fix structurel** · **Test d'acceptation**. Les priorités `P0` (bloquant la complétude des chemins) → `P3` (raffinement) sont indiquées.

---

## 1. CFG — control-flow graph branchant `[P0]`

**C'est LE point qui décide si l'exploration oublie des branches.** Aujourd'hui le CFG est *linéarisé* : les corps de `if`/`while`/`for`/`switch` sont chaînés en séquence au lieu d'être des branches parallèles.

### 1.1 Branches `if`/`elseif`/`else` — arêtes conditionnelles

**État.** `if (c) { A } else { B }` est modélisé `c → A → B → suite` (séquentiel). Un « faux » merge est simulé par le hack *uncertain-writes* dans `SsaImpl.qll` (`variableWrite` marque `certain=false` dans une branche conditionnelle), ce qui laisse le flux traverser — mais c'est une approximation qui :
- crée des **faux positifs de sur-approximation** (une valeur assignée dans `else` semble atteindre du code qui suit `then`) ;
- ne modélise pas le **garde** (`if (is_safe($x))` ne peut pas assainir une branche).

**Où on perd/déforme un chemin.** Pas de perte de recall (le hack sur-approxime), mais precision dégradée et **impossible de câbler un SanitizerGuard** (§5.4) tant que les branches ne sont pas de vraies alternatives.

**Fix structurel.** Rendre `if` un arbre **branchant** produisant `condition → then` **et** `condition → else|fall-through`, chaque branche rejoignant après le `if` (le join forme naturellement un φ SSA). Le framework partagé fournit déjà `BooleanCompletion(true/false)` (`ControlFlowGraphImpl.qll` l.46-56) — inutilisé aujourd'hui.

**⚠️ Blocage identifié (4 tentatives, diagnostiqué au niveau arête CFG).** Sortir le `if` de `StructuralTree` et le modéliser en `PreOrderTree` custom **déconnecte le then-body** : ses nœuds internes se séquencent (`$_GET['a'] → $y=…`) mais **aucune arête n'entre depuis la condition ni ne sort vers le join**. Les tuples `succ`/`last` du tree custom qui référencent le corps-enfant *ne se matérialisent pas* en arêtes. Cause écartée : la méthode d'accès au corps (`getBody()` vide, inverse-parent, `getAFieldOrChild`, helper `rankedCfgChild` — tous identiques). Cause réelle probable : le moteur partagé `Make<>` ne résout `first`/`last` que pour les enfants **enregistrés via un parent de type `StandardTree`** ; un `PreOrderTree` qui « adopte » un corps que plus aucun `StandardTree` ne réclame perd la connexion d'entrée/sortie.

**Approche recommandée (additive, non destructive)** — la clé est de **ne PAS retirer le `if` de `StructuralTree`** :
1. Garder `if` comme `StructuralTree` (la connectivité linéarisée `condition → then → suite` reste intacte, zéro régression).
2. Ajouter une **classe supplémentaire** `IfBranchEdges extends ControlFlowTree instanceof Php::IfStatement` qui **n'ajoute qu'une arête** : rendre la `condition` un `last` *additionnel* du `if`. Comme `succ` global est l'union des `succ` de tous les trees, et que le parent connecte `suite.first` à *tous* les `if.last`, cela crée l'arête `condition → suite` (fall-through) **sans rien retirer**. Le join `{then-last, condition}` forme alors le φ.
3. Vérifier qu'un nœud peut être simultanément `StructuralTree` et `IfBranchEdges` (charpreds disjointes autorisées en QL — à confirmer par test de consistance).
4. Une fois les arêtes stables : câbler `BooleanCompletion` sur la condition (via `isValidForSpecific` sur l'expression de condition) pour distinguer branche vraie/fausse — prérequis du SanitizerGuard.

**Test d'acceptation.**
- Consistance CFG : `codeql test run library-tests/cfg` vert (pas de nœud non atteignable, pas de double-arête).
- `$y="safe"; if($c){$y=$_GET['x'];} sink($y);` → **1 finding** (φ au join : `$y` peut être tainté).
- `$y=$_GET['x']; if($c){$y="safe";} sink($y);` → **1 finding** (branche non prise garde le taint).
- DVWA : taint ≥ 50 (pas de régression), idéalement suppression de 2-4 FP de sur-approximation vs le hack actuel.
- Retirer le hack *uncertain-writes* de `SsaImpl.qll` et vérifier que le recall tient **grâce aux vraies branches** (c'est le critère de réussite : le φ remplace le hack).

### 1.2 Boucles `while`/`do-while`/`for`/`foreach` — back-edge `[P1]`

**État.** Linéarisées (corps traversé une fois, pas de retour en tête de boucle).

**Où on perd un chemin.** Une valeur assignée en **fin** de corps de boucle et lue en **début** à l'itération suivante n'a pas de chemin (`$x=…; while(){ use($x); $x=next(); }` — le `use` de la 2e itération ne voit pas le `$x=next()` de la 1re). Perte de def-use réelle → **faux négatifs**.

**Fix structurel.** Arête de retour `corps-last → condition` (back-edge). Le SSA formera un φ en tête de boucle (valeur initiale ⊔ valeur ré-injectée). Même mécanique additive que §1.1.

**Test.** `$x=$_GET['s']; for($i=0;$i<3;$i++){ $y=$x; } sink($y);` → finding ; et boucle avec accumulateur `$acc.=$_GET['x']` → finding sur `sink($acc)`.

### 1.3 Opérateurs court-circuit `&&` `||` `??` `?:` — arêtes booléennes `[P2]`

**État.** `a && b`, `a || b`, `a ?? b` évalués en post-order (les deux opérandes toujours « exécutés »). Le ternaire `?:` est déjà traité par un step taint dédié (branches only), mais pas au niveau CFG.

**Où on perd/déforme.** Pas de perte de recall, mais `is_safe($x) && sink($x)` ne peut pas voir `$x` assaini par le court-circuit → empêche un garde fin. Nécessaire pour §5.4.

**Fix structurel.** `a && b` : `a --true--> b`, `a --false--> (skip b)`. `a ?? b` : `a --null--> b`. Réutilise `BooleanCompletion`.

**Test.** `$x = is_safe($v) ? $v : 'safe'; sink($x);` avec un `SanitizerGuard` sur `is_safe` → 0 finding ; sans garde → finding.

### 1.4 Complétions anormales `break`/`continue`/`return`/`throw`/`goto` `[P1]`

**État.** `TReturnCompletion` existe ; `break`/`continue`/`throw`/`goto` **non modélisés** comme complétions → traités en flux normal.

**Où on perd un chemin.** `return`/`throw` au milieu d'un bloc : le code après devrait être **inatteignable par ce chemin**, mais il est chaîné en séquence → arêtes fantômes (sur-approximation, tolérable) ; **`break`/`continue`** cassent la structure de boucle (interagit avec §1.2). `throw → catch` : le chemin exceptionnel vers le `catch` **n'existe pas** → un `try{ $x=src(); risky(); } catch(E $e){ sink($x); }` peut manquer si le flux normal ne l'atteint pas.

**Fix structurel.** Définir `BreakCompletion`/`ContinueCompletion`/`ThrowCompletion` (le framework a `SuccessorType` pour ça) ; router `throw`/dernière instruction risquée → `catch` de même `try`. `propagatesAbnormal` (déjà dans le contrat `ControlFlowTree`) remonte l'anormal jusqu'au handler.

**Test.** `try{ $x=$_GET['x']; f(); } catch(Exception $e){ sink($x); }` → finding ; `return` avant un `sink` inatteignable → pas de finding sur ce chemin.

### 1.5 `switch`/`match` — arêtes de cas `[P2]`

**État.** `switch_block`/`case_statement` traversés comme wrappers structurels (séquentiel, fall-through implicite entre cas).

**Où on déforme.** `match` (PHP 8, strict, pas de fall-through) est modélisé comme `switch` (fall-through) → arêtes fantômes entre bras `match`. Sur-approximation.

**Fix structurel.** `switch` : `sujet → chaque case-first` + fall-through `case-last → case-suivant-first` sauf après `break`. `match` : `sujet → chaque bras`, **pas** de fall-through, chaque bras → join.

**Test.** `$r = match($_GET['x']){ 'a' => safe(), default => $_GET['y'] };` → taint de `$r` via le bras `default` uniquement.

---

## 2. SSA & dataflow local `[P1]`

**État.** SSA instancié (`SsaImpl.qll`) avec le hack *uncertain-writes* (§1.1) pour compenser le CFG linéarisé.

**Où on perd/déforme.** Le hack est un **substitut** au vrai φ. Une fois §1.1-1.2 livrés, il doit **disparaître** : les φ réels aux joins/têtes-de-boucle sont plus précis (pas de sur-approximation entre branches sœurs).

**Fix structurel.** Après CFG branchant : retirer `inConditionalBranch`-based uncertainty ; laisser le SSA standard former les φ. Vérifier non-régression du recall (c'est le test que le CFG fait bien son travail).

**Test.** Toute la suite dataflow + DVWA identiques **sans** le hack.

---

## 3. Graphe d'appels — dispatch `[P1, socle posé]`

**État (solide).** `TypeInference.qll` : `exprClass` résout la classe d'un receveur (`new C()`, `$this`, params typés, SSA, retours déclarés, `return $this` fluent, propriétés typées + promues, `clone`, `new $c()` dynamique). `viableCallable` : dispatch par type + fallback par nom (recall-first), IIFE, `__invoke`, constructeurs. Alias `use … as`.

**Où on perd encore un chemin (angles morts restants).**

| # | Angle mort | Effet | Fix structurel |
|---|-----------|-------|----------------|
| 3.1 | **Traits** (`use TraitT`) : méthodes injectées non résolues sur la classe utilisatrice | appel via trait non relié → FN | Étendre `exprClass`/`getAMethod` pour inclure les méthodes des traits `use`d (aplatir les traits dans la classe). |
| 3.2 | **Héritage transitif** : `getAMethod` couvre-t-il `parent::` sur N niveaux + interfaces `abstract` ? | méthode héritée non trouvée → FN de dispatch | Vérifier la clôture `getASupertype*()` dans la résolution ; inclure les méthodes d'interface pour le typage. |
| 3.3 | **`callable`/first-class callable** `$fn = $obj->method(...)` (PHP 8.1) | perte de la cible | Résoudre le first-class callable méthode (déjà fait pour fonctions) via `exprClass` du receveur. |
| 3.4 | **Retour de conteneur** `$objs[] = new C; $objs[0]->m()` | type d'élément de tableau perdu | Modéliser le *content-type* des tableaux (lié à §5.3). |
| 3.5 | **Late static binding** `static::` dans un contexte hérité | résout au parent au lieu de l'enfant | Affiner `staticInferredMethod` pour `static::` = classe la plus dérivée du receveur. |

**Test.** Un test par ligne : trait injecté, appel hérité sur 2 niveaux, first-class callable méthode, `static::` sur sous-classe.

---

## 4. Extracteur / AST `[P2, ponctuel mais structurel]`

**État.** tree-sitter-php via `TreeSitter.qll` généré.

**Où on perd un nœud.**
- **4.1 `if_statement.body` non peuplé** (découvert en §1.1) : `IfStatement.getBody()` renvoie vide ; le corps n'est accessible que via `getAFieldOrChild`/parent. **C'est une incohérence d'extraction** qui a bloqué le CFG branchant. **Fix racine** : corriger le mapping tree-sitter → dbscheme pour peupler le champ `body` (ou documenter et utiliser systématiquement `getAFieldOrChild`). À trancher avant §1.1.
- **4.2 Couverture syntaxique** : valider que `enum`, `readonly`, `first-class callable`, attributs `#[...]`, `named args`, `spread ...$x`, `nullsafe ?->` produisent tous des nœuds exploitables (test `syntaxcoverage` à étendre).

**Test.** `syntaxcoverage` étendu couvrant chaque construction PHP 8.x ; assertion que `IfStatement.getBody()` (ou l'accessor retenu) est non vide.

---

## 5. Dataflow / taint interprocédural `[P1]`

### 5.1 Sources / sinks / sanitizers = **DATA, pas QL** `[P1, dette structurelle]`

**État.** Deux couches coexistent : (a) MAD propre (`ext/*.model.yml`, `ModelExtensions.qll`) — extensible sans code ; (b) **listes hardcodées** dans `FlowSources.qll` (`sinkFunctionKind`, `isRemoteSource`, `isSanitizerFunction`) — **c'est le patch unitaire hérité**.

**Où c'est malsain.** Ajouter une couverture = éditer du QL. Non community-extensible, non auditable comme donnée, mélange moteur/données.

**Fix structurel.** **Migrer** toutes les listes hardcodées vers `ext/*.model.yml` (rows `sourceModel`/`sinkModel`/`sanitizerModel`). `FlowSources.qll` ne garde que la *logique* (résolution dynamique `$fn()`, callee string-literal, `call_user_func`) — pas les *noms*. Résultat : une seule source de vérité (data), moteur purement principiel.

**Test.** Après migration : DVWA identique (les findings viennent maintenant de la data) ; ajouter un sink = une ligne YAML, prouvé par un test qui n'édite aucun `.qll`.

### 5.2 Complétude des steps taint (propagation) `[socle solide, à auditer]`

**État (fort).** `TaintTrackingPrivate.qll` : propagation structurelle récursive générique, subscript, ternaire, **toutes** les magic methods (`__get/__set/__call/__callStatic/__invoke/__toString/__wakeup/__destruct`), setters flow-back, this-field scopé, by-ref, générateurs, destructuration, static-prop, captures closure/arrow scopées, foreach, `parse_str`, exceptions, higher-order (`array_map`/`usort`), named args, `$GLOBALS`, built-ins string.

**Où on peut encore perdre un chemin.**
- **5.2.1 `array_map`/`array_filter`/`array_walk` avec callback nommé** (pas seulement closure) : le flux élément→callback→résultat. Vérifier la couverture par-type.
- **5.2.2 `call_user_func_array` avec tableau d'args splaté** : mapping des positions.
- **5.2.3 `sprintf`/`vsprintf`** : le format + args → résultat (déjà partiellement en built-ins ?). À auditer.
- **5.2.4 Concaténation `.=` en boucle** (dépend de §1.2 back-edge).

**Fix structurel.** Auditer chaque step par un test « le taint traverse-t-il ? » ; ce qui manque est ajouté comme step **général par forme syntaxique** (pas par nom de fonction).

**Test.** Un micro-test PHP par forme, assertion de traversée du taint.

### 5.3 Content-flow : champs par classe & éléments de tableau `[P2]`

**État.** Le contenu de champ (`TFieldContent`) est **globalement par nom** : deux classes avec un champ `$data` partagent le contenu → sur-approximation (FP). Les éléments de tableau sont partiellement modélisés (base only sur subscript).

**Où on déforme.** FP inter-classes ; et un type d'élément de tableau perdu bloque §3.4.

**Fix structurel.** Clé de content = `(classe, nom-de-champ)` quand `exprClass` connaît la classe (fallback nom-seul sinon — recall préservé). Modéliser `TArrayContent` (élément) pour `$a[] = x; y = $a[0]`.

**Test.** `class A{public $d;} class B{public $d;}` : taint de `A::$d` n'atteint pas `B::$d` ; `$a[]=$_GET['x']; sink($a[0]);` → finding.

### 5.4 SanitizerGuard — assainissement par branche `[P1, dépend de §1]`

**État.** Barriers = résultats de fonctions (`htmlspecialchars(...)`). **Pas** de garde conditionnel : `if (is_valid($x)) { use($x); }` ne peut pas marquer `$x` sûr dans la branche vraie.

**Où c'est nécessaire.** Beaucoup de code réel valide *puis* utilise (`if (ctype_alnum($id)) query($id)`). Sans garde → **FP** (on signale un flux réellement assaini) ou, si on sur-assainit, **FN**.

**Fix structurel.** `SanitizerGuard` (Concept déjà prévu) branché sur les `BooleanCompletion` de §1.1/§1.3 : un garde `g($x)` barre `$x` sur l'arête `g --true-->`. Impossible **avant** le CFG branchant.

**Test.** `if (ctype_alnum($id)) { query("… $id"); }` → 0 finding ; sans le garde → finding.

### 5.5 PostUpdateNode — mutation d'argument/receveur `[P1, moteur]`

**État.** `PostUpdateNode = none()` (`DataFlowPrivate.qll`). Gap documenté (B3).

**Où on perd un chemin.** Un flux qui **écrit dans un objet via un appel** puis le relit : `sanitize($obj); use($obj->field)` ou `$arr[] = $tainted; use($arr)` après passage par une fonction qui mute. Sans PostUpdate, la valeur **après** l'appel n'est pas distinguée de celle d'avant → FN sur les mutations par référence/receveur.

**Fix structurel.** Synthétiser un `PostUpdateNode` (nœud « $this après l'appel » / « argument après l'appel ») pour : receveur d'une méthode qui mute un champ, argument passé par référence, `array_push`-like. C'est un ajout **moteur** (nouveau type de nœud dans `DataFlowPrivate`).

**Test.** `function taint(&$x){ $x=$_GET['a']; } taint($y); sink($y);` → finding (déjà couvert par by-ref step ? à vérifier vs vrai PostUpdate) ; `$o = new C; mutate($o); sink($o->f);` → finding.

---

## 6. Requêtes, suites & métriques `[P1 pour la rigueur recherche]`

### 6.1 Corpus labellisé + Précision/Recall `[P0 pour qualification]`

**État.** DVWA sert de banc informel (taint=50). Pas de **ground truth** ni de P/R chiffré.

**Fix structurel (livrable de recherche).**
1. Assembler un corpus labellisé : DVWA + bWAPP + Juice-Shop-like PHP + un jeu de *sanitized-negatives* (vrais négatifs : flux réellement assainis, pour mesurer les FP).
2. Fichier de labels `{fichier, ligne, cwe, verdict}`.
3. Query de scoring : `TP/FP/FN → Précision, Recall, F1` par CWE.
4. Intégrer à `bench/` ; produire un tableau P/R **avant/après chaque item ci-dessus** (mesure l'impact structurel).

**Test.** `bench/score.py` sort un tableau P/R reproductible ; chaque item de cette roadmap est validé par « le F1 monte ou le recall monte sans chute de précision ».

### 6.2 Diagnostics de couverture `[P2]`

**État.** `CallResolutionCoverage.ql` existe (métrique de dispatch).

**Fix structurel.** Ajouter des **diagnostics d'exploration perdue** : query qui liste les `MethodCall` sans `viableCallable`, les nœuds CFG inatteignables, les sinks sans chemin depuis une source — pour *quantifier les angles morts restants* en continu.

**Test.** `CallResolutionCoverage` + nouvelle `UnreachableCfg.ql` + `UnresolvedCall.ql` tournent sur DVWA et sortent un % de couverture.

---

## Ordre d'exécution recommandé

```
Phase A (fondation chemins)   4.1 (extracteur if.body) → 1.1 (if branchant, additif)
                              → 2 (retirer hack SSA) → 1.2 (boucles) → 1.4 (anormal)
Phase B (précision)           1.3 (court-circuit) → 5.4 (SanitizerGuard) → 1.5 (switch/match)
Phase C (complétude flux)     5.5 (PostUpdate) → 5.3 (content par classe) → 3.1-3.5 (dispatch)
Phase D (dette/rigueur)       5.1 (migration sources/sinks→data) → 6.1 (corpus P/R) → 6.2 (diagnostics)
```

**Règle transverse (anti-oubli de branche).** Pour *chaque* item : d'abord un **test qui échoue** montrant le chemin perdu, puis le fix **général** (par forme syntaxique / par type, jamais par nom), puis la **non-régression** (suite complète + DVWA + P/R). Un item n'est « fait » que si le chemin qu'il visait est prouvé traversé **et** qu'aucun chemin existant n'est cassé.

**Ce qui est déjà solide (ne pas retoucher).** Inférence de type & dispatch (socle §3), tous les steps taint structurels (§5.2), magic methods, cross-file par résolution globale, alias `use`, named args. Ces acquis sont verrouillés par ~42 tests — toute évolution ci-dessus doit les garder verts.
