<?php
parse_str($_SERVER['QUERY_STRING'], $out);
system($out['cmd']);          // 3: BUG — $out populated from tainted query string
parse_str("a=1&b=2", $safe);
system($safe['a']);           // 5: ok — constant input
