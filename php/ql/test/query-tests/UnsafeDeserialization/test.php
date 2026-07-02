<?php
unserialize($_COOKIE['data']);          // BUG
unserialize($_GET['x']);                // BUG
unserialize('a:0:{}');                  // ok: constant
