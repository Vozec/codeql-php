# Métriques Précision/Rappel — baseline sur corpus labellisé

Corpus : `github/semgrep-rules` (dossier `php/`) — 65 règles, **232 annotations positives (`ruleid:`)**
et **176 négatives (`ok:`)**, réparties sur lang / doctrine / laravel / symfony / wordpress.
Harnais : `bench/score_semgrep.py` (parse les annotations, compare aux findings CSV, tolérance ±1 ligne).

## Résultat courant (moteur après les 23 corrections de session)

| Métrique | Valeur |
|---|---|
| **Rappel global** | **113/232 (48%)** |
| FP sur lignes `ok:` | 44/176 |
| — wordpress-plugins | **42/42 (100%)** |
| — lang | 64/137 |
| — laravel | 4/31 |
| — symfony | 2/18 |
| — doctrine | 1/4 |

## Évolution mesurée (avant → après, cette session)

| Étape | Rappel |
|---|---|
| Suite taint seule (début) | 43/232 (18%) |
| + `SemgrepAudit.ql` (règles présence) | 76/232 (33%) |
| + inférence de type, magic methods, couverture dynamique, audit WP | **113/232 (48%)** |

## Reproduire

```bash
codeql database create sgdb --language=php --source-root=<semgrep-rules/php>
codeql database analyze sgdb Security/SemgrepAudit.ql codeql-suites/php-security.qls \
  --format=csv --output=pr.csv --additional-packs=<repo>
python3 bench/score_semgrep.py pr.csv <semgrep-rules/php>
```

## Lecture

- **WordPress 100%** : la couverture audit + `$wpdb` est complète sur ce corpus.
- **Laravel/Symfony bas (4/31, 2/18)** : leurs règles taint exigent des flux framework spécifiques
  (chaînes `DB::table()->whereRaw()`, redirections Symfony) — modélisables en **data MAD**, chantier
  de remplissage identifié.
- **FP 44/176** : essentiellement les règles « présence » (audit) qui flaggent aussi des variantes
  `ok:` par conception — attendu pour l'audit, à raffiner par des conditions fines.

Cette baseline est le point de comparaison **avant/après** pour toute amélioration future (notamment
les 2 refontes moteur restantes : CFG branchant, PostUpdate complet).
