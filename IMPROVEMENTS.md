# Pistes d'amélioration — CodeQL-for-PHP

> État au 2026-07-05, après le modèle inter-objets + la validation vrai-code.
> Effort : **S** (heures) · **M** (1-2 j) · **L** (semaine+). Impact : 🔴 fort · 🟠 moyen · 🟢 faible.

---

## 0. État du benchmark (mesuré, corrigé) — PAS de régression

Corpus labellisé `github/semgrep-rules/php` (232 positifs, 176 négatifs), harnais `bench/run.sh` :

| Configuration | Rappel | FP sur `ok:` |
|---|---|---|
| Ancienne baseline (AUDIT §6.1) | 113/232 (48%) | 44/176 |
| **Fin de session (suite + `SemgrepAudit.ql`)** | **139/232 (59%)** | **40/176** |
| Queries taint SEULES (sans audit) | 75/232 (32%) | 9/176 |
| par cat. | wordpress **42/42** · lang 75/137 · **symfony 13/18** · laravel 8/31 · doctrine 1/4 |

**+26 points de rappel ET −4 FP vs la baseline historique.** Détail des gains cette session : couverture
WordPress/include/array-callable/clone/laravel-colonnes/dynamic-dispatch, sources qualifiées-classe (D2),
et **queries pattern précises Symfony CORS + CSRF (+13, 0 FP)** écrites pour éviter les pièges `ok:` du
corpus (valeur `*`/`false` exacte, classe `*Response`, extension `framework`).

**La « régression 48%→25% » était un ARTEFACT DE MESURE** : `SemgrepAudit.ql` est taggé `@tags audit`,
donc le sélecteur `security-extended` l'exclut ; ma re-mesure `database analyze` de la suite seule ne le
comptait pas, alors que l'ancienne baseline l'incluait (le corpus a ~77 positifs en `*/security/audit/`,
dont wordpress 42/42 vient à 100% de l'audit présence-based). En le ré-incluant : **52% > 48%**, même 44 FP,
**plus** les gains taint de cette session (taint-seul 60→75, FP stable à 9). `bench/run.sh` inclut
désormais `SemgrepAudit.ql` pour une mesure de parité fidèle.

**Vraies pistes de rappel restantes** (non-artefact) :
1. **Taint framework Laravel/Symfony** (4/31, 0/18) — beaucoup de ces positifs sont des règles
   NON-injection (mass-assignment, env-exposure, config) → nécessitent de **nouvelles queries** (pas des
   modèles). Les sinks injection (DB::raw/whereRaw, andWhere, redirect) sont déjà couverts.
2. **Audit doctrine/symfony/sha224** — `SemgrepAudit.ql` couvre WordPress+lang mais pas encore
   `doctrine-*-dangerous-query`, `symfony-csrf/redirect/cors`, `sha224-hash`, `openssl-decrypt-validate`.
3. **~99 positifs `lang` non-taint** (weak-crypto, random, debug) → queries pattern/audit à écrire.

> **44 FP** = coût inhérent des règles audit présence-based (flaguent tout `eval`/`system`/… y compris sur
> `ok:`). Sémantiquement identique au comportement de semgrep pour ces règles. Réductible en affinant
> `SemgrepAudit.ql` (contexte), mais pas « faux » au sens strict.

---

## A. Couverture / faux négatifs (chemins ratés)

**Recheck syntaxe exotique (fait cette session)** — 9.5/11 constructs PHP 8.x OK : `match`, args nommés,
nullsafe, arrow / static arrow, heredoc, throw-expression, `list()` imbriqué, classe anonyme, générateur,
interpolation avec appel de méthode, ternaire, `[...$a]` (clé string). Inter-objets exotiques OK : trait,
factory statique chaînée, dispatch d'interface. **Corrigés** : array-callable (A2 ✅), `include/require`
(✅), `new $c()` + callback HO teinté (✅), **`clone $a` préserve le taint des champs (✅)**.

| # | Manque | Impact | Effort |
|---|---|---|---|
| A4 | **`compact()` / `extract()`** (résolution variable↔nom dynamique) — confirmé FN | 🟠 | L |
| A9 | **Flow summaries pour builtins en first-class-callable** `strval(...)` / `$f='strval'; $f($t)` — le callable résout vers une fonction SANS corps, donc pas de flux arg→retour | 🟠 | L |
| A10 | **Spread positionnel → variadic** `f(...[$t])` avec `$a[0]` — le contenu du tableau ne rejoint pas les lectures de `$a` (le spread à clé string marche) | 🟢 | M |
| A6 | **`use A\{B,C}` groupé** — `resolveClassReference` ignore le préfixe de groupe (dégrade au fallback nom) | 🟠 | M |
| A7 | **Clés de tableau** — `$a['x']=$t; $a['y']` FP (clés conflées). **Investigué** : un modèle de contenu key-sensitive (`TKnownArrayContent(key)` + wildcard) NE SUFFIT PAS — l'étape taint générique `base→subscript` (TaintTrackingPrivate:214) re-taint toute lecture d'élément et est **porteuse pour `$_GET['x']`** (le pattern source dominant). Fix réel = rendre cette étape key-sensitive ET faire que les sources-tableau (`$_GET`) teintent au contenu wildcard. Plus gros qu'estimé, risque élevé | 🔴 | L |
| A8 | **PHPDoc / génériques** dans `TypeInference` (`@param`/`@return`/`@var`, collections Laravel) → dispatch parfois raté | 🟠 | L |

---

## B. Précision / faux positifs (recall-first assumé mais à surveiller)

| # | Problème | Impact | Effort |
|---|---|---|---|
| B1 | **Content de champ instance-insensible** — `$a->put($t); $b->pull()` (instances distinctes) → FP. Limite fondamentale, gros chantier moteur | 🟠 | L |
| B2 | **Heuristique "instance-field via $this" coarse** — set/read cross-méthode SANS chemin d'objet → FP sur grosses classes. À remplacer par une analyse d'état plus fine | 🟠 | M |
| B3 | **`__toString`/`__set` fallback type-inconnu** — matchent toute classe déclarant la magie (borné mais cross-classe) | 🟢 | M |
| B4 | **`getConstructCallee` par nom court** (DataFlowPrivate:102) — pas namespace-aware (l'étape taint l'est déjà) | 🟠 | S |
| B5 | **Guards seulement `if` positif** — early-return `if(!g($x))return;`, `else`, chaînes `&&` non couvertes | 🟢 | M |

---

## C. Performance

| # | Piste | Impact | Effort | Mesuré |
|---|---|---|---|---|
| C1 | **`defaultAdditionalTaintStep` cher sur code OO** — 42s Laravel (somme des steps manuels). Migrer vers MAD (§D1) réduit ce coût | 🔴 | M | profilé |
| C2 | **`variableRead` alourdi** — Piece 1 (store-base-as-read) +67s WordPress. Cibler seulement les bases passées à un appel | 🟠 | M | profilé |
| C3 | **Coût CFG inhérent** — `Cfg::MakeWithSplitting` 208s WordPress (lib partagée, sans splitting) — difficile à réduire | 🟢 | L | profilé |
| C4 | **Full Laravel + tests lent (>8min)** — les fichiers de test (mocks/closures massifs) coûtent disproportionnément | 🟠 | M | profilé |
| C5 | **`sameScope`/`getParent+`** — 18s WordPress ; précalculer `enclosingScope(node)` en relation cachée | 🟠 | M | profilé |
| C6 | **`getASuccessor+` du post-update step** — déjà mitigé (pilote par petit ensemble) ; reste une fermeture transitive | 🟢 | S | — |

> ✅ Déjà fait cette session : reorder post-update (WordPress 2.9×), `getContentApprox` grossier (Laravel 2.8×).

---

## D. Architecture interne / dette de layering (« pas de cas-par-cas »)

| # | Dette | Impact | Effort |
|---|---|---|---|
| ~~D3~~ ✅ | **FAIT** — `sanitizerGuardModel(name)` extensible ; les 14 noms ctype_/is_/in_array/preg_match en MAD ; structure `isGuardedRead` reste en QL | 🟠 | S |
| ~~D4~~ ✅ | **FAIT** — escapers-méthode `quote`/`escape`/`real_escape_string` → `sanitizerModel` method rows ; `isSanitizer` ne garde que le cast (construct) | 🟠 | S |
| D1 | **Dispatch HO-callback hardcodé × 3** — `array_map`/`usort`/`call_user_func` énumérés dans TaintTrackingPrivate + FlowSources ×2. Créer `callbackModel(name,callbackArg,dataArg)` + 1 step générique. **Note** : c'est une énumération STABLE de builtins (pas du bricolage) ; refactor DRY à faire prudemment (3 usages de flux délicats) | 🟠 | M |
| D2 | **Sources/sinks `method` par nom bare** — schéma **qualifié-classe** dans `callMatches` → `Request::get`/`$request->input` précis. Bénéfice corpus limité sans stubs de types (résolution du receveur) | 🟠 | M |
| D5 | **`parse_str` out-ref hardcodé** → extensible `outRefModel(kind,name,fromArg,toRefArg)` | 🟢 | M |
| D6 | **frameworks.model.yml redondant** — recouvre laravel/symfony/wordpress (doublons `e`/`esc_*`/`createQuery`/…). Les BUGS (e-sink, selectRaw arg -1) sont corrigés ; dédup complète = surface de bug en moins | 🟠 | S |
| D7 | **Phase D — `Php::*` privé incomplet** — API AST publique existe mais `Php::*` fuit dans certains corps ; finir pour la mergeabilité upstream | 🟠 | L |

---

## E. Extraction / robustesse

| # | Item | Impact | Effort |
|---|---|---|---|
| E1 | **`function readonly()` non parsé** — limite grammaire tree-sitter-php 0.24.2 (2 fichiers WordPress). Fix = update grammaire vendorée (Cargo + re-vendoring Bazel), risqué. Dégradation gracieuse aujourd'hui | 🟢 | L |
| E2 | **Diagnostics d'extraction non exposés** — les parse-errors sont des WARN CLI, pas des diagnostics CodeQL. Ajouter une query `Diagnostics/ExtractionCoverage.ql` | 🟠 | M |
| E3 | **Pas de `downgrades`** dbscheme (compat multi-versions CodeQL) | 🟢 | S |

---

## F. Validation / méthode / CI

| # | Item | Impact | Effort |
|---|---|---|---|
| ~~F2~~ ✅ | **FAIT** — `.github/workflows/php-qltest.yml` : job `qltest` (suite) + job `benchmark` (échoue si rappel < `bench/baseline.txt`). `bench/run.sh` = extract+analyse(security+audit)+score en 1 commande | 🟠 | M |
| F1 | **Élargir la vérité-terrain** — corpus semgrep-rules en place (232/176, baseline committée) ; ajouter OWASP Benchmark PHP + apps CVE réelles | 🟠 | M |
| F3 | **Suite de tests** — beaucoup de query-tests mono-fichier ; élargir les cas inter-fichiers (1 ajouté) et par-query | 🟠 | M |
| F4 | **Comparatif Semgrep/Psalm** sur les mêmes cibles pour repérer les trous de couverture | 🟢 | M |

---

## G. Packaging / mergeabilité upstream

| # | Item | Impact | Effort |
|---|---|---|---|
| G1 | Docs diary (AUDIT/IMPROVEMENTS) → README racine + `php/docs/` propres | 🟢 | S |
| G2 | Vendoring Bazel complet (fait minimal) — vérifier la CI Bazel upstream | 🟠 | M |
| G3 | `.qhelp` / `@precision`/`@tags` QA sur chaque query | 🟢 | S |
| G4 | Change-notes par release formalisées | 🟢 | S |

---

## Fait cette session (2026-07-05)

✅ Benchmark corrigé (artefact SemgrepAudit) + baseline committée + **CI garde-fou** (F2).
✅ Couverture : WordPress complet, `include`/`require`, array-callables, `new $c()`, callback HO teinté,
   `clone`, injection nom-de-colonne Laravel.
✅ Précision : `e`/selectRaw/header (B) — FP 44→40.
✅ **Layering COMPLET** : D1 (callbackModel MAD), D2 (sources qualifiées-classe `typedSourceModel`),
   D3 (guards MAD), D4 (sanitizers-méthode MAD), D5 (`outRefModel`), D6 (dédup frameworks.model.yml).
✅ **Queries pattern précises** : Symfony CORS + CSRF (+13, 0 FP).
✅ Validation : Symfony réel (0 erreur parse, 2s/6s), syntaxe exotique 9.5/11, suite 87→94.
**Rappel 113→139 (48%→59%), FP 44→40.**

## Ordre recommandé (reste)

1. **symfony non-literal-redirect (2)** — source `$request->query->get()`/`$session->get()` (typedSourceModel + stubs).
2. **doctrine dangerous-query (dbal)** — nécessite def-use du `$sql` variable (concat en amont) ; le sous-cas
   inline-concat seul donne +0/+1 FP (essayé, reverté). weak-crypto : idem, précision (les `ok:` du corpus
   testent `md5(...)===` strict) — pas de version présence-based sans FP.
3. **A7 (clés de tableau)** 🔴 — nécessite de rendre l'étape taint générique `base→subscript` key-sensitive
   (porteuse pour `$_GET['x']`) — gros chantier moteur, risque élevé.
4. **F1 (élargir corpus : OWASP Benchmark PHP)** · **C1/C2 (perf) · B1/B2 (instance-sensitivity)** ·
   **D7 (Phase D) · G (packaging)** — mergeabilité upstream.
