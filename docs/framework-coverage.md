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
| **Laravel** | ✅ `request()`/`Request::*` (typed) | ✅ raw + column builders (`whereRaw`, `orderBy`, `max`…) | ✅ echo/`<?=`/`Str::markdown`; ⚠️ Blade `{!! !!}` file-syntax | ✅ `Http::get/post` (typed) | ✅ `Storage::get/put/download` (typed) | ✅ `redirect`/`->to`/`->away` | ✅ (`unserialize`) | ✅ `e`/`validate`/`Str::slug` | ✅ `Str::*`/`Arr::*`/Collection | ✅ `Route::get/…/match` closures |
| **Symfony / Doctrine** | ✅ `Request` + bags (`InputBag`/`ParameterBag`/… typed) | ✅ DBAL `executeQuery`/`fetch*`/DQL `andWhere` | ✅ echo/`<?=`; ⚠️ Twig `\|raw` file-syntax | ⚠️ `HttpClient::request` (name-only) | ✅ Filesystem `dumpFile`/`appendToFile`/`mirror` | ✅ `redirect`/`setTargetUrl` | ✅ (`unserialize`) | ✅ Twig `escape` + `Connection::quote` (typed) | ✅ String component `u()`/… | ✅ `#[Route]` attribute actions |
| **Magento 2** 🧪 | ✅ `getParam`/`getPostValue` + `Http::getQuery` (typed) | ✅ `rawQuery` + `AdapterInterface::query` (typed) | ✅ `.phtml` echo/`<?=` | ✅ `Curl::get/post` (typed) + `makeRequest` | ✅ `fileGetContents`/`filePutContents`/… | ✅ `_redirect`/`setRedirect` | ✅ `SerializerInterface::unserialize` | ✅ `Escaper::escape*` + `quote` (typed) | ⚠️ `getData` (coarse) | n/a (declarative `routes.xml` → source is `getParam`) |
| **Joomla 3/4/5** 🧪 | ✅ `getRaw`/`getHtml` + `Input::get` (typed, J3+J4) | ✅ `setQuery` | ✅ echo/`<?=` | ✅ `Http::get/post/request` (typed) | ✅ `File::read/delete` | ✅ `$app->redirect` | ✅ (`unserialize`) | ✅ `getInt/getUint/…` filters + `quote`/`escape` (typed) | ❌ | n/a (MVC `task` dispatch → source is `Input::get`) |
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
- ✅ **Attribute/annotation routing** (Symfony `#[Route('/u/{id}')] public function show(int $id)`): the
  scalar action parameters become sources via the generic `routeAttributeModel` (data row: the attribute
  short-name, e.g. `Route`), tracked interprocedurally into the action.
- ✅ **`Route::resource('photos', PhotoController::class)` / `apiResource`** — the conventional RESTful
  actions that receive the `{resource}` id (`show`/`edit`/`update`/`destroy`) have their scalar id
  parameter resolved as a source (via `routeResourceModel`).
- **n/a — declarative routing** (Magento `routes.xml`, Joomla `task=`, TYPO3): there is no per-route
  callable; user input enters through the request object (`getParam`/`Input::get`) which *is* modeled
  as a source, so no route mechanism is needed.

## Templating

Two distinct template risks are modeled:

- **Output XSS** — tainted data reaching page output. Covered: `echo`, `print`, `<?= … ?>` short-echo
  tag (the workhorse of `.phtml` / WordPress & Magento themes / compiled Blade & Twig), `printf` /
  `vprintf` / `print_r`, WordPress `_e` / `_ex` / `wp_die`, and framework raw-HTML helpers that bypass
  auto-escaping (`Str::markdown` / `inlineMarkdown`) modeled as taint steps so they still reach the echo.
- **Server-side template injection (SSTI)** — a user-controlled *template string* reaching a compiler:
  Twig `createTemplate` / `render`, Blade `Blade::render` / `compileString`, Smarty `fetch` / `display`,
  Latte `renderToString`, Mustache `loadTemplate`, generic `compile` (see `ext/templating.model.yml`).

**Gap — template-engine source syntax.** Blade `{!! $x !!}` and Twig `{{ x|raw }}` are template-file
syntax, not PHP calls — the PHP extractor sees them as HTML text, so raw output written *in the template
file* is not tracked. This needs a Blade/Twig grammar or a precompile step. **Note:** if you analyze
*compiled* templates (Laravel `storage/framework/views`, Twig `var/cache`), they are plain PHP `echo`
and fully covered — pointing the scan at the compiled views is the practical workaround.

## Known gaps (what is NOT supported)

- **Template-engine source syntax** (Blade `{!! $x !!}`, Twig `{{ x|raw }}` written in `.blade.php` /
  `.twig` files): template-file syntax, not a PHP call — see the Templating section (compiled templates
  ARE covered). PHP-level output (`echo`/`print`/`<?=`/`printf`) is fully modeled.
- **Class-property sources** (WordPress `WP::$query_vars`, `WP_Query::$query_vars`): field access, not
  a call, so not expressible as a method row.
- 37/40 patterns in the ComplexFlows test suite flow — constructor-promoted fields, private
  setter/getter, DI-typed request properties (on `vendor/` classes), fluent collection/string pipelines,
  magic `__get`/`__set`, generators, `array_map`/`merge`/`column`, `parse_str` out-refs, interpolated
  method calls (incl. heredoc), by-reference `foreach` write-back, nullsafe `?->` chains, named args &
  named-key spread, multi-condition `match`, `??=`, `data_get`, string-transform builtins, and
  controller/attribute/resource route params — with interprocedural tracking across several call layers.
  The remaining gaps are engine/static-analysis-complexity limits, not data fixes:
  - **`extract()` / `compact()`** (`extract($_GET)` creates `$id`, `$name`, … from array keys): dynamic
    variable creation/reading — the variable names are data-dependent, a universal static-analysis limit.
  - **Interprocedural `throw`/`catch`** (a `throw` inside a *called* function, caught in the caller): the
    shared engine has no exceptional dataflow; a **local** `try { throw new Exception($x); } catch ($e) {
    $e->getMessage() }` IS tracked, only the throw-across-a-call-boundary case is not.
  - Note `MyEnum::tryFrom($input)->value` is intentionally NOT flagged — a backed-enum value is bounded
    to the enum's declared constants (an allow-list), so it is not attacker-controlled.

  Now covered (previously gaps): by-reference `foreach` write-back, `array_walk` by-reference callback
  write-back, local `throw`/`catch` message, first-class-callable to a builtin, and **static-local
  persistence across calls** (`static $s; $s = $tainted;` read on a later invocation — modelled as a
  function-scoped jump step, like `$GLOBALS`).
  - **Exception message across throw/catch** (`throw new Exception($tainted)` … `catch ($e) {
    $e->getMessage() }`): a *local* exception message flows (`new Exception($x); $e->getMessage()` is
    modelled), but the engine does not track throw→catch exceptional control flow, so the message is lost
    when it crosses a `throw`/`catch` boundary.
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

**Typed models resolve against the written type name, not just declared classes.** A receiver's class is
matched by type *inference* (declared/instantiated classes) OR by the type *annotation* it carries
(`function store(Request $request)`, `private Request $req`) — so the class-scoped models fire even when
the framework class lives in an un-extracted `vendor/` (the normal case for real projects). Without this,
every typed source/sink/sanitizer would silently miss on real framework code.
