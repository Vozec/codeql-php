<?php
// Modern SSRF: user-controlled URL reaches an HTTP client request method.
function g($client) {
    $url = $_GET['url'];
    $client->request('GET', $url);       // 6: BUG (Guzzle request, URI arg 1)
}
function g2($client) {
    $client->getAsync($_GET['u']);       // 9: BUG (Guzzle getAsync, URI arg 0)
}
function safe($client) {
    $client->request('GET', 'https://api.internal/health');  // 12: safe (constant URL)
}
