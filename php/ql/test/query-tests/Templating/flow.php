<?php
// Templating output (XSS) + template injection (SSTI) coverage.

// 1. plain echo — baseline XSS sink
echo $_GET['a'];                                        // WANT xss

// 2. short-echo tag <?= ?> — the workhorse of PHP templates (.phtml, WP/Magento themes)
?>
<div><?= $_GET['b'] ?></div>
<?php

// 3. printf — output XSS sink
printf($_GET['c']);                                     // WANT xss

// 4. raw-HTML helper: Str::markdown returns unescaped HTML that is echoed (Blade {!! !!} analog)
echo \Illuminate\Support\Str::markdown($_GET['d']);     // WANT xss

// 5. SSTI: a user-controlled TEMPLATE STRING reaches a render call → code execution
$twig->render($_GET['f']);                               // WANT ssti

// 6. SSTI: Smarty fetch with a user template
$smarty->fetch($_GET['g']);                              // WANT ssti

// 7. safe: escaped output must NOT flow
echo htmlspecialchars($_GET['h']);                       // ok
