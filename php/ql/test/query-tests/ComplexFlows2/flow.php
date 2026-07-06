<?php
// COMPLEX real-world flows, batch 2. Source = $_GET, sinks = system()/DB sinks.

// 1. array_map with an inline closure over tainted elements
$m1 = array_map(function ($x) { return $x; }, [$_GET['a']]); system($m1[0]);   // WANT array-map-closure

// 2. by-reference out parameter (parse_str writes into $out)
parse_str($_GET['a'], $out); system($out['x']);                // WANT parse-str-outref

// 3. deeply nested array assignment then read
$d3 = []; $d3['a']['b']['c'] = $_GET['a']; system($d3['a']['b']['c']);  // WANT nested-deep-array

// 4. chained builtin transforms
system(trim(strtolower(substr($_GET['a'], 0, 10))));           // WANT chained-transforms

// 5. spread of a tainted array into a new array literal
$s5 = [...$_GET]; system($s5['x']);                            // WANT spread-superglobal

// 6. Eloquent-style: set a model attribute from input, read it back
class UserM { public $name; }
$u6 = new UserM(); $u6->name = \request('n'); system($u6->name);  // WANT eloquent-attr (request() source)

// 7. Laravel request->validated() returns the (still user-controlled) validated data
class Ctrl7 {
    public function store(\Illuminate\Http\Request $request) {
        $v = $request->validate(['name' => 'required']);       // validate() returns user data (not sanitized)
        \DB::statement("SELECT " . $v['name']);                // WANT validated-still-tainted
    }
    // typed request param + a TYPED-only accessor (header) — needs exprTypeName (Request is in vendor/)
    public function h2(\Illuminate\Http\Request $req) { system($req->header('X-Forwarded-For')); }  // WANT typed-header
}

// 8. DI container resolution of the request
$req8 = app(\Illuminate\Http\Request::class); system($req8->input('a'));  // WANT container-resolve (likely gap)

// 9. taint through a helper that returns via a local variable across a branch
function pick9($x) { if (strlen($x) > 3) { $y = $x; } else { $y = $x; } return $y; }
system(pick9($_GET['a']));                                     // WANT branch-join-return

// 10. foreach over tainted assoc array, key AND value
foreach ($_GET as $k => $v10) { system($v10); }               // WANT foreach-superglobal-value

// 11. typed Request PARAM (not property) + input() — isolate param-exprClass for typed sources
function ti11(\Illuminate\Http\Request $r) { system($r->input('a')); }  // WANT param-typed-input
