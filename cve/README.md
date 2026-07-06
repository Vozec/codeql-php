# CVE corpus — post-2023 PHP vulnerabilities

Faithful **minimal** PoCs reproducing the *vulnerable code pattern* of real, published CVEs (2023+)
across every PHP framework/CMS this analyzer models. Each file is a self-contained reduction of the
advisory's source→sink flow — enough to exercise the taint model, not a runnable exploit.

Purpose: a regression + generalization corpus. The same query/model that flags the reduced pattern here
finds the *class* of bug wherever it recurs. Several models/rules were added specifically to catch these
patterns (see git history + the ▸ notes below), so they — and their lookalikes elsewhere — now are.

## Layout

```
cve/<framework>/CVE-YYYY-NNNNN.php   # header cites the advisory; sink line preceded by `// ruleid: <query>`
cve/run.sh                           # extract cve/ → analyze (php-security-extended) → score
cve/score.py                         # compares SARIF vs. the `// ruleid:` annotations (±1 line)
```

Run: `bash cve/run.sh` — reports DETECTED n/N annotated sinks + any un-annotated findings.

## Status: 19 / 24 annotated sinks detected, 0 false positives

### Detected ✅

| CVE | Framework | Class | Caught by |
|-----|-----------|-------|-----------|
| CVE-2024-27956 | WordPress (WP-Automatic) | SQL injection | `$_REQUEST` → `$wpdb->get_results` |
| CVE-2024-2879 | WordPress (LayerSlider) | SQL injection | `$_GET` → `$wpdb->get_results` |
| CVE-2024-1071 | WordPress (Ultimate Member) | SQL injection | `sanitize_text_field($_POST)` → `$wpdb` (weak-XSS-sanitizer fix) |
| CVE-2024-25600 | WordPress (Bricks) | code injection (RCE) | `$_POST` → `eval` |
| CVE-2024-9634 | WordPress (GiveWP) | object injection | `$_POST` → `unserialize` |
| CVE-2023-6989 | WordPress (Shield) | file inclusion (LFI) | `array_merge($_GET,$_POST)` → `include` |
| CVE-2024-9047 | WordPress (WP File Upload) | file read + path traversal | `$_COOKIE` → `fopen`/`fread`/`unlink` |
| CVE-2025-8085 | WordPress (Ditty) | SSRF | `$_POST` → `wp_remote_get` |
| CVE-2024-50345 | Symfony (http-foundation) | open redirect | bag `$request->query->get` → `new RedirectResponse` |
| CVE-2024-50342 | Symfony (http-client) | SSRF | bag `$request->request->get` → `HttpClient::request` |
| CVE-2024-13283 | Drupal (Facets) | reflected XSS | bag `$request->query->get` → echo |
| SA-CONTRIB-2023-015 | Drupal (File Chooser Field) | SSRF | `$_POST` → `system_retrieve_file` |
| CVE-2024-32877 | Yii2 | reflected XSS | `Request::get` (typed) → echo |
| CVE-2023-22727 | CakePHP | SQL injection | `ServerRequest::getQuery` → `Query::limit` (new sink) |
| CVE-2025-54418 | CodeIgniter4 | command injection (RCE) | `getClientName` (upload) → `exec` |
| CVE-2024-33266 | PrestaShop (deliveryorderautoupdate) | SQL injection | `Tools::getValue` → `Db::executeS` |
| CVE-2024-28392 | PrestaShop (pscartabandonmentpro) | SQL injection | `Tools::getValue` → `Db::executeS` |
| CVE-2023-24814 | TYPO3 core | persisted XSS | `getIndpEnv` → echo |

### Not yet detected ⚠️ (documented limitations)

| CVE | Framework | Class | Why missed |
|-----|-----------|-------|------------|
| CVE-2023-6360 | WordPress (My Calendar) | SQL injection | source is `$request->get_params()['from']` — array element of a WP_REST_Request method result (accessor + subscript not tracked) |
| CVE-2025-22207 | Joomla (com_scheduler) | SQL injection | fluent taint: `$query->order($dir)` must carry taint into the query object read by `$db->setQuery($query)` |
| CVE-2024-42485 | Laravel (filament-excel) | path traversal | `request()->route('path')` — taint through the `request()` helper's chained `route()` accessor |
| CVE-2024-47186 | Laravel (Filament) | stored XSS | source is a persisted model property (`$record->color`), not a request accessor — needs stored-taint modelling |
| CVE-2024-13297 | Drupal (Eloqua) | object injection | Drupal 7 array-shaped `$form_state['values'][...]` (not the D8 `FormState::getValue()` accessor) |

## Detection improvements driven by this corpus

Added while building the corpus (all data/model-level or small, generalizable QL — benchmark FP
unchanged at 40/176, full test suite green):

- **Symfony/Drupal request-bag idiom** — a structural source for `$request->{query,request,attributes,cookies,files}->{get,all,…}()`, the single most common Symfony/Drupal input accessor.
- **`__construct` typed sinks fire on `new Class($arg)`** — `new RedirectResponse($url)`, `new SplFileObject($path)`, … (previously constructor sinks only matched `Class::__construct()`-style calls).
- **Upload-filename sources** — `getClientName`, `getClientOriginalName/Extension`, `getClientFilename` (the upload-RCE / traversal class).
- **CakePHP `Query::limit`/`offset` SQL sinks** (the exact CVE-2023-22727 vector); **Drupal `system_retrieve_file`/`drupal_http_request` SSRF sinks**.
- **Kind-scoped sanitizers** — `sanitize_text_field`/`sanitize_textarea_field` are now XSS-only barriers that still carry taint to SQL/path sinks, so the sanitize-then-SQLi class (CVE-2024-1071, CVE-2023-6360) is no longer hidden.
- **Soundness: a name-based sanitizer defers to a same-named function defined in the analyzed code** — a custom no-op `sanitize_text_field` is not blindly trusted; its real body is analyzed (regression test `ShadowedSanitizer`).
