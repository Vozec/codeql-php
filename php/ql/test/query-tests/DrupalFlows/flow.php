<?php
// Drupal source -> sink flows.
db_query("SELECT * FROM t WHERE id = " . arg(2));           // WANT SQLi line 3 (arg source + db_query sink)
db_query("SELECT * FROM t WHERE id = " . $_GET['id']);      // WANT SQLi line 4
function h(\Drupal\Core\Form\FormStateInterface $form_state) {                                     // FormStateInterface via annotation below
  db_query("SELECT * FROM u WHERE n = '" . $form_state->getValue('name') . "'");  // WANT SQLi line 6
}
function q(\Drupal\Core\Database\Connection $db) {
  $db->query("DELETE FROM t WHERE id = " . $_GET['id']);    // WANT SQLi line 9 (typed Connection::query)
}
drupal_goto($_GET['dest']);                                  // WANT open-redirect line 11
db_query("SELECT * FROM t WHERE x = " . check_plain($_GET['x']));  // must NOT flow (line 12, sanitized? check_plain is HTML-escape, not SQL — actually still flows for SQL). skip
