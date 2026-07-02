<?php
class A {
  public $data;
  public function set() { $this->data = $_GET['x']; }   // taint into A::$data
  public function get() { system($this->data); }         // 5: MUST flag (same class A)
}
class B {
  public $data;                                          // same field name, different class
  public function get() { system($this->data); }         // 9: must NOT flag (B::$data never tainted)
}
