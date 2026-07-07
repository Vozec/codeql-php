<?php
// Syntax-coverage probe: does taint reach a $wpdb->query() SQL sink through each PHP string-building /
// control syntax? Each `// want N` marks a line that SHOULD be flagged.
function probe($wpdb) {
  $g = $_GET['x'];

  // 1. direct concatenation
  $wpdb->query("SELECT * FROM t WHERE a=" . $g);                 // want 8

  // 2. double-quote interpolation
  $wpdb->query("SELECT * FROM t WHERE a=$g");                    // want 11

  // 3. sprintf
  $wpdb->query(sprintf("SELECT * FROM t WHERE a=%s", $g));       // want 14

  // 4. implode of tainted array
  $wpdb->query("SELECT * FROM t WHERE a IN (" . implode(",", $_GET['ids']) . ")"); // want 17

  // 5. heredoc
  $sql = <<<SQL
SELECT * FROM t WHERE a=$g
SQL;
  $wpdb->query($sql);                                            // want 23

  // 6. .= augmented concat
  $q = "SELECT * FROM t WHERE a=";
  $q .= $g;
  $wpdb->query($q);                                              // want 28

  // 7. str_replace template
  $wpdb->query(str_replace("__A__", $g, "SELECT * FROM t WHERE a=__A__")); // want 31

  // 8. ternary
  $wpdb->query("SELECT * FROM t WHERE a=" . ($g ?: "1"));        // want 34

  // 9. null coalesce
  $wpdb->query("SELECT * FROM t WHERE a=" . ($_GET['y'] ?? "1")); // want 37

  // 10. array element via list-ish
  $arr = [$g, "safe"];
  $wpdb->query("SELECT * FROM t WHERE a=" . $arr[0]);            // want 41

  // 11. strtolower wrapper
  $wpdb->query("SELECT * FROM t WHERE a=" . strtolower($g));     // want 44

  // 12. nested function calls
  $wpdb->query("SELECT * FROM t WHERE a=" . trim(strtoupper($g))); // want 47

  // 13. variable-variable
  $name = "g"; $$name = $g;
  $wpdb->query("SELECT * FROM t WHERE a=" . $gg);                // (dynamic; may miss) want 51 — SKIP if unsupported
}
