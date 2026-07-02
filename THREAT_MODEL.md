# Threat model & soundness assumptions — CodeQL-PHP

Ce document énonce le **périmètre**, les **hypothèses de soundness** et les **limites assumées** de
l'analyseur. Il est requis pour une évaluation scientifique : un outil d'analyse n'a de valeur que si
l'on sait *ce qu'il garantit* et *ce qu'il sur-/sous-approxime*.

## 1. Objectif d'analyse

Détecter les vulnérabilités de type **injection par flux de données teintées** (taint) dans du code
PHP : de sources attaquant-contrôlées vers des puits dangereux, sans passer par un assainisseur.
Classes couvertes : command/SQL/code injection, path traversal, XSS, SSRF, LDAP, désérialisation,
open redirect, file inclusion, clés crypto en dur, type juggling.

## 2. Modèle d'attaquant

L'attaquant contrôle les **entrées de requête** (superglobales `$_GET/_POST/_REQUEST/_COOKIE/_SERVER/`
`_FILES`, helpers de framework) et, pour l'analyse de gadgets, l'**état d'objets désérialisés**
(`unserialize` de données non fiables → champs de `__wakeup`/`__destruct`).

## 3. Ce qui est SOUND (sur le fragment statique de PHP)

Sur le sous-ensemble *statiquement résoluble* du langage, l'analyse vise la soundness (pas de faux
négatif) :

- Flux de valeur local (SSA) : affectations, augmentées, destructuring, `foreach`.
- Flux interprocédural : appels résolus par **nom** (fonctions) et par **type** (méthodes/statiques
  quand le type du receveur est inféré), avec repli par nom (recall-first) sinon.
- Propagation structurelle récursive (accès `[]`/`->`/`::`, opérateurs, concat, interpolation, casts).
- Sensibilité aux champs (content model tableau/propriété).
- Cross-fichier : analyse whole-program (tous les `.php` d'une base, résolution globale par symbole).

## 4. Ce qui est SUR-APPROXIMÉ (recall-first → faux positifs possibles, jamais silencieux)

Choix explicite : privilégier le rappel. Ces approximations peuvent produire des faux positifs
**visibles** (jamais un faux négatif silencieux) :

- Résolution d'appel par **nom** en repli (une méthode `X` peut cibler toute méthode `X`).
- Contenu de champ **clé par nom** (deux classes partageant un nom de champ peuvent se mélanger — sauf
  `$this->f` désormais scopé par classe).
- Index de tableau **insensible à la clé** (recall-first) en complément du content model.
- Magic `__toString` : repli type-agnostique borné quand le type n'est pas inféré.

## 5. Ce qui est SOUS-APPROXIMÉ / NON MODÉLISÉ (limites assumées → faux négatifs possibles)

Le dynamisme de PHP rend certaines constructions **indécidables** (théorème de Rice). Sont hors
périmètre ou partiellement modélisés — documentés comme tels :

- `eval()` / `assert()` de code dynamique (détecté comme puits, mais le code évalué n'est pas analysé).
- Variables 100% dynamiques non résolubles : `$$x` où `$x` n'est pas résoluble par SSA.
- `extract()` / `compact()` / `parse_str()` (blanchiment array→variables) — non modélisé.
- Réflexion (`ReflectionClass`, `call_user_func` sur nom calculé non résoluble).
- **PostUpdate moteur incomplet** : mutations d'objet via méthode couvertes pour le motif *setter*
  (`$o->set($t); use($o->f)`), mais pas de manière générale (by-ref value-return, mutations profondes).
- **CFG linéarisé** : pas de sensibilité aux chemins ; les gardes conditionnels (`if (ctype_alnum…)`)
  n'assainissent pas encore (compensé partiellement par des writes de branche « incertains »).
- Alias `use ... as` suivis dans le même fichier uniquement ; alias de fonction non suivis.
- Second-order / stored (persistance en base puis relecture) : non modélisé.

## 6. Sanitizers : hypothèse de correction

Un modèle d'assainisseur suppose que la fonction/méthode nommée **assainit réellement**. Pour éviter
les faux négatifs dus à des homonymes trompeurs (ex. un `prepare()` custom non sûr), les sanitizers
sensibles sont **typés** (`typedSanitizerModel` : ne s'appliquent que sur le type de receveur attendu).

## 7. Extensibilité (Models-as-Data)

Sources, puits, étapes de propagation et assainisseurs des frameworks sont déclarés en **données**
(`ext/*.model.yml`) : ajouter un framework ne modifie ni le moteur ni les requêtes. Les hypothèses
ci-dessus s'appliquent aux modèles fournis (Laravel, Symfony/Doctrine, WordPress, PrestaShop, TYPO3).

## 8. Reproductibilité de l'évaluation

Baseline de non-régression : suite de tests QL (`php/ql/test/`) + corpus DVWA (recall/précision suivis
à chaque changement). Métrique de couverture de résolution : `Diagnostics/CallResolutionCoverage.ql`.
Cible d'évaluation à venir (Phase 6) : corpus labellisé (OWASP PHP Benchmark + CVE réels avec commit de
correction) pour des chiffres précision/rappel avant/après chaque amélioration.
