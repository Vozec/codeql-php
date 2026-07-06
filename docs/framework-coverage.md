# Framework coverage

What the analyzer models for each PHP framework/CMS, and — just as important — **what it does not yet
model** (so gaps are visible). Everything here is *data* in `php/ql/lib/ext/<framework>.model.yml`;
adapting a new framework is a data file, never an engine change. See
[adapting-frameworks.md](adapting-frameworks.md) for the how-to.

**Legend** — ✅ modeled · ⚠️ partial / high-FP-risk names only-if-distinctive · ❌ not modeled ·
🧪 modeled but not yet validated against a test corpus · n/a not applicable to that framework.

## Coverage matrix

| Framework | Request sources | SQLi sink | XSS sink | SSRF sink | Path sink | Redirect sink | Deserialize | Sanitizers | Taint steps | Route→source |
|---|---|---|---|---|---|---|---|---|---|---|
| **Core PHP** (built-ins) | ✅ superglobals, `filter_input`, `getenv` | ✅ `mysql*/mysqli*/pg_query` | ✅ `echo`/`print` | ✅ `curl_*`/`fsockopen`/`get_headers` | ✅ `fopen`/`file`/`hash_file`/… | ✅ `header` | ✅ `unserialize` | ✅ `htmlspecialchars`/`intval`/`basename`/… | ✅ string built-ins | n/a |
| **WordPress** | ✅ `$_*`, `wp_unslash`, `WP_REST_Request::get_*` | ✅ `$wpdb->query/get_*` | ✅ `_e`/`_ex`/`wp_die` | ✅ `wp_remote_*`/`download_url`/`fetch_feed` | ✅ `wp_delete_file` | ✅ `wp_redirect` | ✅ `maybe_unserialize` | ✅ `esc_*`/`sanitize_*`/`wp_kses*` + `$wpdb->prepare` | ✅ `add_query_arg`/`wp_unslash`/`map_deep` | ✅ `add_shortcode` atts |
| **Laravel** | ✅ `request()`/`Request::*` (typed) | ✅ raw + column builders (`whereRaw`, `orderBy`, `max`…) | ⚠️ Blade `{!! !!}` is template syntax (❌) | ✅ `Http::get/post` (typed) | ✅ `Storage::get/put/download` (typed) | ✅ `redirect`/`->to`/`->away` | ✅ (`unserialize`) | ✅ `e`/`validate`/`Str::slug` | ✅ `Str::*`/`Arr::*`/Collection | ✅ `Route::get/…/match` closures |
| **Symfony / Doctrine** | ✅ `Request` + bags (`InputBag`/`ParameterBag`/… typed) | ✅ DBAL `executeQuery`/`fetch*`/DQL `andWhere` | ⚠️ Twig `\|raw` is template syntax (❌) | ⚠️ `HttpClient::request` (name-only) | ✅ Filesystem `dumpFile`/`appendToFile`/`mirror` | ✅ `redirect`/`setTargetUrl` | ✅ (`unserialize`) | ✅ Twig `escape` + `Connection::quote` (typed) | ✅ String component `u()`/… | ❌ `#[Route]` attribute params (see gaps) |
| **Magento 2** 🧪 | ✅ `getParam`/`getPostValue` + `Http::getQuery` (typed) | ✅ `rawQuery` + `AdapterInterface::query` (typed) | ⚠️ `.phtml` echo (core PHP) | ✅ `Curl::get/post` (typed) + `makeRequest` | ✅ `fileGetContents`/`filePutContents`/… | ✅ `_redirect`/`setRedirect` | ✅ `SerializerInterface::unserialize` | ✅ `Escaper::escape*` + `quote` (typed) | ⚠️ `getData` (coarse) | n/a (declarative `routes.xml` → source is `getParam`) |
| **Joomla 3/4/5** 🧪 | ✅ `getRaw`/`getHtml` + `Input::get` (typed, J3+J4) | ✅ `setQuery` | ⚠️ echo (core PHP) | ✅ `Http::get/post/request` (typed) | ✅ `File::read/delete` | ✅ `$app->redirect` | ✅ (`unserialize`) | ✅ `getInt/getUint/…` filters + `quote`/`escape` (typed) | ❌ | n/a (MVC `task` dispatch → source is `Input::get`) |
| **PrestaShop** | ✅ `Tools::getValue` | ✅ `Db::executeS` | ❌ | ❌ | ❌ | ✅ `Tools::redirect*` | ❌ | ✅ `pSQL`/`bqSQL` | ❌ | n/a |
| **TYPO3** | ✅ `GeneralUtility::_GP/_GET/_POST` | ✅ `sql_query`/`exec_SELECTquery` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `quoteStr`/`fullQuoteStr` | ❌ | n/a |

## Route → source support

An HTTP handler's user-controlled parameters become taint sources via the generic
`routeHandlerModel(subjectKind, name, handlerArgIndex)` mechanism, then the **interprocedural** engine
carries the taint through however many function/method calls the handler makes before reaching a sink
(the real-world case — the bug is usually several calls deep, not in the handler itself). A parameter is
a route source when it is untyped or **scalar-typed** (`int $id`, `string $slug`); parameters typed as a
class (a DI service or model-bound object) are excluded.

- ✅ **Closure handlers** — `Route::get('/u/{id}', fn($id) => …)`, `add_shortcode('t', fn($atts) => …)`.
- ✅ **Controller handlers** — `Route::get('/u/{id}', [UserController::class, 'show'])`,
  `Route::delete('/u/{id}', 'UserController@destroy')`: the resolved action method's scalar parameters
  become sources, tracked interprocedurally into the action's call graph.
- ⚠️ **`Route::resource(...)` / `apiResource(...)`** — maps to conventional controller methods
  (`index`/`show`/`update`/…) by naming convention; those method params are not yet resolved (partial).
- ❌ **Attribute/annotation routing** (Symfony `#[Route]` on a controller action): the placeholders bind
  to method parameters with no call site (no `routeHandlerModel` shape), so this needs a dedicated
  attribute-driven QL source. **Known gap.**
- **n/a — declarative routing** (Magento `routes.xml`, Joomla `task=`, TYPO3): there is no per-route
  callable; user input enters through the request object (`getParam`/`Input::get`) which *is* modeled
  as a source, so no route mechanism is needed.

## Known gaps (what is NOT supported)

- **Template-engine output** (Blade `{!! !!}`, Twig `|raw`, `.phtml` unescaped echo of `getData()`):
  raw-output is template syntax, not a PHP call — needs template extraction / a template analyzer.
- **Symfony `#[Route]` attribute parameters** as sources (structural, not data — see above).
- **Class-property sources** (WordPress `WP::$query_vars`, `WP_Query::$query_vars`): field access, not
  a call, so not expressible as a method row.
- **Context/flow-dependent audit rules**: `openssl-decrypt-validate` (needs HMAC-validation context),
  `base-convert-loses-precision`, `md5-used-as-password` (needs value flow) — the same call is safe or
  unsafe depending on surrounding code, so no precise syntactic rule exists.
- **Nested-array handlers** (WordPress `register_rest_route($ns, $r, ['callback' => …])`): the handler
  is inside an array argument, not a positional one; the current route mechanism resolves positional
  closures only.
- **Magento/Joomla** models (🧪) are researched from the official docs but not yet validated against a
  test corpus — recall on real Magento/Joomla code is unmeasured (they carry the same FP guarantees as
  the corpus-validated frameworks: no new false positives on the benchmark's 176 negative cases).

## Precision guarantees

Every row is chosen to keep the benchmark's false-positive count unchanged (currently 40/176 negatives).
Generic method names (`get`/`query`/`request`/`read`/`quote`) are **class-scoped** via `typedSourceModel`
/ `typedSinkModel` / `typedSanitizerModel` so they only fire on the right framework class. Kind-specific
sanitizers that would mask other vuln classes (e.g. an XSS-only escaper clearing SQLi) are deliberately
omitted.
