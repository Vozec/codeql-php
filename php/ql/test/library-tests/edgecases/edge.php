<?php $u = $_GET['a']; ?>
<p>html</p>
<?php system($u); ?>
<?php
$x = $_GET['b'] ?? 'd';
system($x);
$y = true ? $_GET['c'] : 'd';
system($y);
$h = <<<CMD
run $u
CMD;
system($h);
call_user_func('system', $_GET['e']);
$r = $_GET['f'];
$s =& $r;
system($s);
