<?php
// Attacker-controlled class names and higher-order callbacks are arbitrary-code-execution sinks.

// Dynamic class instantiation: the class NAME comes from the request.
$o1 = new $_GET['cls']();                       // BUG
$c = $_POST['cls'];
$o2 = new $c();                                 // BUG
$o3 = new Logger();                             // safe: constant class

// Tainted callback passed to a higher-order built-in.
usort($items, $_GET['cmp']);                    // BUG (callback at arg 1)
array_map($_GET['fn'], $items);                 // BUG (callback at arg 0)
array_filter($items, $_GET['pred']);            // BUG (callback at arg 1)
preg_replace_callback('/x/', $_GET['cb'], $s);  // BUG (callback at arg 1)
usort($items, 'strcmp');                        // safe: constant callback
array_map('trim', $items);                      // safe
