<?php
// Real-world COMPLEX taint flows (not basic CTF). Source = $_GET, sink = system() (command injection).
// Each `// WANT` sink line must receive taint. Failures reveal where source/step/flow recognition breaks.

// 1. constructor-promoted field: taint into a DTO field, read back out
class Dto1 { public function __construct(public $data) {} }
$d1 = new Dto1($_GET['a']); system($d1->data);                 // WANT ctor-promoted-field

// 2. classic setter/getter over a private field
class Bag2 {
    private $v;
    public function set($x) { $this->v = $x; }
    public function get() { return $this->v; }
}
$b2 = new Bag2(); $b2->set($_GET['a']); system($b2->get());    // WANT setter-getter

// 3. DI-injected typed Request property + typed source (framework input via property)
class Ctrl3 {
    public function __construct(private \Illuminate\Http\Request $request) {}
    public function handle() { $x = $this->request->input('id'); system($x); }  // WANT di-typed-request
}

// 4. fluent query-builder chain — sink is on a chained method whose receiver comes from the chain
function q4() {
    \DB::table('users')->where('active', 1)->orderBy($_GET['col']);  // WANT fluent-chain-sink (orderBy col SQLi)
}

// 5. collection pipeline: taint through collect()->map()->implode()
$c5 = collect($_GET['a'])->map(function ($x) { return $x; })->implode(',');
system($c5);                                                    // WANT collection-pipeline

// 6. json_decode wrapper then array access
$j6 = json_decode($_GET['a'], true); system($j6['x']);         // WANT json-decode-array

// 7. taint stored in a static property, read elsewhere
class St7 { public static $cache; }
St7::$cache = $_GET['a']; system(St7::$cache);                  // WANT static-property

// 8. taint through an array pushed then popped
$a8 = []; $a8[] = $_GET['a']; system(array_pop($a8));           // WANT array-push-pop

// 9. object returned from a factory method (typed return) then field read
class Model9 { public $name; }
class Repo9 { public function find(): Model9 { $m = new Model9(); $m->name = $_GET['a']; return $m; } }
$r9 = new Repo9(); system($r9->find()->name);                  // WANT factory-return-field

// 10. taint through str_replace transformation then concat
$s10 = str_replace('x', 'y', $_GET['a']); system("echo " . $s10);  // WANT transform-concat
