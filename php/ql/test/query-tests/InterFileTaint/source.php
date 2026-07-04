<?php
namespace App\Http;
class Request {
    private $data;
    public function __construct() { $this->data = $_GET; }
    public function input(string $key) { return $this->data[$key]; }   // source-carrying
}
