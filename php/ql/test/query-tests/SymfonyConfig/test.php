<?php
// Symfony misconfiguration audit: permissive CORS wildcard + disabled CSRF protection.

// --- Permissive CORS (wildcard Access-Control-Allow-Origin) ---
$a = new Response('c', 200, ['Access-Control-Allow-Origin' => '*']);        // BUG
$b = new JsonResponse('c', 200, ['Access-Control-Allow-Origin' => '*']);    // BUG
$resp->headers->set('  access-control-allow-origin  ', ' * ');              // BUG
$c = new Response('c', 200, ['Access-Control-Allow-Origin' => 'https://ok.com']); // safe: specific
$d = new Bag('c', 200, ['Access-Control-Allow-Origin' => '*']);             // safe: not a Response
$resp->headers->set('Access-Control-Allow-Origin', 'https://ok.com');       // safe: not wildcard

// --- CSRF protection disabled ---
$resolver->setDefaults(['csrf_protection' => false]);                       // BUG
$resolver->setDefaults(['csrf_protection' => $flag]);                       // BUG: variable
$container->prependExtensionConfig('framework', ['csrf_protection' => false]); // BUG
$resolver->setDefaults(['csrf_protection' => true]);                        // safe: enabled
$container->prependExtensionConfig('framework', ['csrf_protection' => null]);   // safe: null
$container->prependExtensionConfig('other_bundle', ['csrf_protection' => false]); // safe: wrong ext

// --- Non-literal redirect target ---
class Ctrl {
    function a($t) { return $this->redirect($t); }               // BUG: variable target
    function b($t) { return $this->redirect('https://'.$t); }    // BUG: concatenation
    function c() { return $this->redirect('https://safe.example'); } // safe: literal
    function d($t) { return $this->redirectToRoute($t); }        // safe: route method
}
