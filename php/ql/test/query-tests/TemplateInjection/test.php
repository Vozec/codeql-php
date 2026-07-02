<?php
// Server-side template injection: a user-controlled TEMPLATE reaches a render/compile call.

// Twig string loader
function twig($twig) {
    $tpl = $_GET['tpl'];
    $twig->createTemplate($tpl);         // 7: BUG (SSTI via Twig createTemplate)
}

// Smarty fetch with user template
function smarty($smarty) {
    $smarty->fetch("string:" . $_GET['t']);   // 12: BUG (SSTI via Smarty fetch)
}

// Blade render of a raw template string (static)
function blade() {
    Blade::render($_POST['tpl'], []);    // 17: BUG (SSTI via Blade::render)
}

// safe: constant template
function safe($twig) {
    $twig->createTemplate("Hello {{ name }}");  // 22: safe (constant template)
}
