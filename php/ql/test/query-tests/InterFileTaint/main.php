<?php
namespace App;
use App\Http\Request;
use App\Service\Runner;
$req = new Request();
$runner = new Runner($req);
$runner->handle($_GET['action']);   // source -> Runner::handle -> req->input -> trait execute -> system (3 files)
