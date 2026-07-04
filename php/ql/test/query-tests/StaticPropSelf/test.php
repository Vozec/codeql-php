<?php
// `self::$p` / `static::$p` are the enclosing class's static property (normalize the scope to that class).

class Reg {
    public static $data;
    function write() { self::$data = $_GET['a']; }
    function read()  { system(self::$data); }        // 7: BUG (same class, self::)
}

class Reg2 {
    public static $data;
    function write() { static::$data = $_GET['b']; }
    function read()  { system(static::$data); }       // 13: BUG (same class, static::)
}

// two unrelated classes sharing a static-prop name must NOT cross-link
class X { public static $data; function w() { self::$data = $_GET['c']; } }
class Y { public static $data; function r() { system(self::$data); } }   // 18: safe

// `new self()` inside a factory resolves to the enclosing class (type inference)
class Box {
    public $v;
    static function make() { return new self(); }
}
$b = Box::make();
$b->v = $_GET['d'];
system($b->v);                                        // 27: BUG
