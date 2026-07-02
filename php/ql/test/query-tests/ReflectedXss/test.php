<?php
echo $_GET['name'];                     // BUG
print($_POST['x']);                     // BUG
echo htmlspecialchars($_GET['n']);      // ok: escaped
echo "static";                          // ok: constant
