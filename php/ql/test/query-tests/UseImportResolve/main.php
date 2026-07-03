<?php
namespace Web;
use App\Runner;                 // non-aliased import: bare `Runner` -> App\Runner
function handle() {
    $r = new Runner();
    $r->run($_GET['x']);        // 6: BUG (dispatch resolves Runner via the `use` import)
}
