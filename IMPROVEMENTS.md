# Pistes d'amélioration — CodeQL-for-PHP

> État au 2026-07-05, après le modèle inter-objets + la validation vrai-code.
> Effort : **S** (heures) · **M** (1-2 j) · **L** (semaine+). Impact : 🔴 fort · 🟠 moyen · 🟢 faible.

---

## 0. État du benchmark (mesuré, corrigé) — PAS de régression

Corpus labellisé `github/semgrep-rules/php` (232 positifs, 176 négatifs), harnais `bench/run.sh` :

| Configuration | Rappel | FP sur `ok:` |
|---|---|---|
| Ancienne baseline (AUDIT §6.1) | 113/232 (48%) | 44/176 |
| **Suite sécurité + `SemgrepAudit.ql`** (parité semgrep) | **122/232 (52%)** | 44/176 |
| Queries taint SEULES (sans audit) | 75/232 (32%) | **9/176** |
| par cat. (avec audit) | wordpress **42/42** · lang 75/137 · laravel 4/31 · symfony 0/18 · doctrine 1/4 |

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

| # | Manque | Impact | Effort |
|---|---|---|---|
| A1 | **Sinks/sources framework** (WordPress `wp_remote_*`/`$wpdb`, Laravel Eloquent `DB::raw`/`whereRaw`, Symfony) — cf. §0 | 🔴 | M |
| A2 | **`call_user_func([$obj,'m'], $t)`** (callable tableau `[obj,method]`/`[class,method]`) | 🟠 | M |
| A3 | **FCC stocké en array** `$a=[f(...)]; $a[0]($t)` ; **arrow imbriqué** `fn()=>fn()=>$x` | 🟢 | M |
| A4 | **`compact()` / `extract()`** (résolution variable↔nom dynamique) | 🟠 | L |
| A5 | **`parent::method()` / `parent::$prop`** (self/static faits, parent non) | 🟠 | S |
| A6 | **`use A\{B,C}` groupé** — `resolveClassReference` ignore le préfixe de groupe (dégrade au fallback nom) | 🟠 | M |
| A7 | **Clés de tableau** — `$a['x']=$t; $a['y']` : `TArrayContent()` conflate les clés → passer à `TArrayContent(key)` pour clés constantes | 🟠 | L |
| A8 | **PHPDoc / génériques** dans `TypeInference` (`@param`/`@return`/`@var`, collections Laravel) → dispatch parfois raté | 🟠 | L |
| A9 | **Flow summaries riches** (arg→champ, arg→arg) pour libs sans corps — au-delà des `stepModel` simples | 🟠 | L |

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
| D1 | **Dispatch HO-callback hardcodé × 3** — `array_map`/`usort`/`call_user_func` énumérés dans TaintTrackingPrivate:503 + FlowSources:156/164 (triplé, incohérent). Créer `callbackModel(kind,name,callbackArg,dataArg)` extensible + 1 step générique | 🔴 | M |
| D2 | **Sources/sinks `method` par nom bare** — besoin d'un schéma **qualifié-classe** dans `callMatches` (ModelExtensions) → `Request::get`/`$request->input` précis, remet les sources retirées (cf. §0) | 🔴 | M |
| D3 | **Guards `ctype_*`/`is_*` hardcodés** (FlowSources:48) → extensible `sanitizerGuardModel` + MAD | 🟠 | S |
| D4 | **Sanitizers-méthode hardcodés** `quote`/`escape` (FlowSources:77) → `sanitizerModel`/`typedSanitizerModel` en DATA | 🟠 | S |
| D5 | **`parse_str` out-ref hardcodé** → extensible `outRefModel(kind,name,fromArg,toRefArg)` | 🟢 | M |
| D6 | **Double mécanisme inter-objets** — modèle générique (PostUpdate) + heuristiques recall (instance-field, promotion). Documenter OU unifier (promotion via store implicite) | 🟠 | M |
| D7 | **Phase D — `Php::*` privé incomplet** — API AST publique existe mais `Php::*` fuit dans certains corps/utilitaires ; finir pour la mergeabilité upstream | 🟠 | L |

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
| F1 | **Élargir la vérité-terrain** — le corpus semgrep-rules existe (232/176) ; ajouter OWASP Benchmark PHP + apps CVE réelles, et **automatiser la re-mesure** (garde-fou anti-régression de rappel — cf. §0 qui serait passée inaperçue sans ça) | 🔴 | M |
| F2 | **CI** — workflow : build extracteur → suite → analyse d'un projet de référence + score bench, à chaque commit | 🟠 | M |
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

## Ordre recommandé

1. **§0 + A1 (couverture framework WordPress/Laravel/Symfony)** 🔴 — récupère le rappel perdu ; re-mesurer après chaque ajout.
2. **D2 + D1 (sources qualifiées-classe + callbackModel)** 🔴 — résorbe le layering, ré-arme la recall SANS FP, **et** accélère (§C1).
3. **F1/F2 (bench automatisé + CI)** 🔴 — garde-fou : une régression de rappel comme §0 doit échouer la CI.
4. **C1/C2 (perf steps OO) · A7 (clés tableau) · B1/B2 (instance-sensitivity)** 🟠 — précision & vitesse.
5. **D7 (Phase D) · G (packaging)** 🟠 — mergeabilité upstream.
