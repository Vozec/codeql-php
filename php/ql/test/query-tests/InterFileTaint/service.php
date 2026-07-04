<?php
namespace App\Service;
use App\Http\Request;
trait Runs { public function execute($cmd) { \system($cmd); } }        // sink in a trait
class Runner {
    use Runs;
    private $req;
    public function __construct(Request $r) { $this->req = $r; }
    public function handle(string $key) { $this->execute($this->req->input($key)); }  // taint: req->input -> execute (trait) -> system
}
