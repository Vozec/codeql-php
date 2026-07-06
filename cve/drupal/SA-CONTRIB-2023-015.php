<?php
// SA-CONTRIB-2023-015 (no CVE) — file_chooser_field 7.x < 1.13 — SSRF.
// A FAPI #value_callback POST value is split and the remote URL fetched with no host validation.
// Source: $_POST['file_chooser_field']. Sink: system_retrieve_file($url).
// Ref: https://www.drupal.org/sa-contrib-2023-015
function download($destination) {
    $input = $_POST['file_chooser_field'];
    list($class, $remote) = explode("::::", $input);
    // ruleid: php/ssrf
    return system_retrieve_file($remote, $destination);
}
