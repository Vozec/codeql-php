<?php
system($_GET['cmd']);
$c = $_POST['c'];
exec($c);
$id = $_GET['id'];
mysqli_query($conn, "SELECT * FROM u WHERE id=" . $id);
$name = $_GET['name'];
echo "Hello $name";
echo htmlspecialchars($_GET['x']);
echo "static content";
function wrap($v) { return $v; }
system(wrap($_POST['ip']));
eval($_REQUEST['code']);
$clean = intval($_GET['n']);
system($clean);

class Db {
    function run($sql) { return mysqli_query($this->c, $sql); }
}
$db = new Db();
$db->run("SELECT * FROM u WHERE id=" . $_GET['mid']);
