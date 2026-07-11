<?php
// file_get_contents('php://input') is the raw HTTP request body (a remote source); a file_get_contents
// of an ordinary path is NOT a source.
function handle() {
    system(file_get_contents('php://input'));      // BUG: raw request body is user input
}

function config_cmd() {
    system(file_get_contents('/etc/app/config'));  // safe: ordinary file read, not a request source
}
