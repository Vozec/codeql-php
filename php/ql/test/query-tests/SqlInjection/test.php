<?php
$id = $_GET['id'];
mysqli_query($conn, "SELECT * FROM u WHERE id=" . $id);   // BUG
$q = "SELECT * FROM u WHERE n='" . $_POST['n'] . "'";
mysql_query($q);                                          // BUG via var
pg_query("SELECT 1");                                     // ok: constant
mysqli_query($conn, "SELECT * FROM u WHERE id=" . intval($_GET['id'])); // ok: intval
