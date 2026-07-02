<?php
eval($_GET['code']);                    // BUG
$fn = $_POST['f']; $fn($_GET['a']);     // BUG: controllable callee
assert($_REQUEST['a']);                 // BUG
eval("return 1+1;");                    // ok: constant
