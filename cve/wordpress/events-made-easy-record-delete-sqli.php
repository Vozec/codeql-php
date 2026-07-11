<?php
// Events Made Easy < 2.2.81 — SQL injection via the generic AJAX record-delete (WPScan-tracked).
// eme_ajax_record_delete() concatenates $_POST[$postvar] (the id list) straight into a
// DELETE ... WHERE ... IN (...) run via $wpdb->query with no escaping/cast; it is reached from the
// manage-* AJAX handlers. Real code, verbatim from eme_functions.php / eme_templates.php.
// Source: $_POST['id']. Sink: $wpdb->query() (arg0).
// Flow: eme_ajax_manage_templates -> eme_ajax_record_delete -> $wpdb->query.
// Ref: https://wpscan.com/vulnerability/ff5fd894-aff3-400a-8eec-fad9d50f788e/ ;
//      downloads.wordpress.org/plugin/events-made-easy.2.2.80.zip (eme_functions.php)
function eme_ajax_manage_templates() {
    eme_ajax_record_delete('eme_templates', 'eme_cap_templates', 'id');
}

function eme_ajax_record_delete($table, $cap, $postvar) {
    global $wpdb;
    // $_POST[$postvar] concatenated into the IN(...) list with no escaping/cast
    // ruleid: php/sql-injection
    $wpdb->query("DELETE FROM $table WHERE $postvar in ( " . $_POST[$postvar] . ")");
}
