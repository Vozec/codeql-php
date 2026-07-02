<?php
namespace App;

interface Animal { public function speak(): string; }

trait Loggable {
    public function log(string $m): void {}
}

abstract class Pet implements Animal {
    use Loggable;
    public function __construct(protected string $name) {}
    abstract public function speak(): string;
    public static function create(string $n): static { return new static($n); }
}

class Dog extends Pet {
    public function speak(): string { return "Woof"; }
    public function __call($m, $a) { return null; }
}
