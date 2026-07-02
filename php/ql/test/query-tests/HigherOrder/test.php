<?php
$arr = [$_GET['x']];
array_map(function($item) { system($item); }, $arr);        // 3: BUG callback-first
$data = [$_GET['y']];
usort($data, function($a) { system($a); return 0; });        // 5: BUG array-first
$safe = ["const"];
array_map(function($z) { system($z); }, $safe);              // 7: ok, constant array
