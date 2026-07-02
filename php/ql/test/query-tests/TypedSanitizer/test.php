<?php
// A CUSTOM prepare() that is NOT a real sanitizer must NOT suppress detection (no false negative).
class MyDb {
    public function prepare($sql) { return $sql; }             // custom, unsafe
    public function run($sql) { mysqli_query($GLOBALS['c'], $sql); }
}
$db = new MyDb();
$db->run($db->prepare("SELECT * FROM u WHERE id=" . $_GET['id']));  // BUG: caught (custom prepare != safe)

// The REAL wpdb::prepare (type-scoped) must stay a sanitizer (no false positive).
function wp() {
    global $wpdb;
    $wpdb->query($wpdb->prepare("SELECT * FROM u WHERE id=%d", $_GET['id'])); // ok: real wpdb::prepare
}
