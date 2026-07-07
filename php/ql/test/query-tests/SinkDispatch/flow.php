<?php
// Sink reached through dynamic dispatch — does the sink model still fire?
function probe($wpdb, $conn) {
  $g = $_GET['x'];
  $sql = "SELECT * FROM t WHERE a=" . $g;

  // 1. direct builtin sink (baseline)
  mysqli_query($conn, $sql);                          // want 8

  // 2. call_user_func on a builtin sink name
  call_user_func('mysqli_query', $conn, $sql);        // want 11

  // 3. call_user_func_array on a builtin sink
  call_user_func_array('mysqli_query', [$conn, $sql]); // want 14

  // 4. variable function holding a sink name
  $fn = 'mysqli_query';
  $fn($conn, $sql);                                   // want 18

  // 5. variable METHOD on $wpdb (sink method via variable)
  $m = 'query';
  $wpdb->$m($sql);                                    // KNOWN MISS 22 (variable method name — dynamic, out of scope)

  // 6. call_user_func array-callable method sink
  call_user_func([$wpdb, 'query'], $sql);             // want 25
}
