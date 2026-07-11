<?php
// ChatBot (WPBot) <= 4.4.6 — unauthenticated SQL injection via the search AJAX `keyword`.
// The wp_ajax_nopriv_wpbo_search_* handlers concatenate $_POST['keyword'] into $wpdb->get_row/
// get_results queries; sanitize_text_field() strips tags but does NOT escape quotes, so a `'` in the
// keyword injects SQL. Real code, verbatim from qcld-wpwbot-search.php (nopriv AJAX). WPScan-tracked.
// Source: $_POST['keyword']. Sink: $wpdb->get_row() (arg0).
// Ref: downloads.wordpress.org/plugin/chatbot.4.4.6.zip (qcld-wpwbot-search.php:49-54)
function qc_wpbo_search_responseby_intent() {
    global $wpdb;
    $keyword = sanitize_text_field($_POST['keyword']);      // source (sanitize_text_field is XSS-only, not SQL)
    $table = $wpdb->prefix . 'wpbot_response';
    // ruleid: php/sql-injection
    $result = $wpdb->get_row("SELECT `response` FROM `$table` WHERE 1 and `intent` = '" . $keyword . "'");
    return $result;
}
add_action('wp_ajax_nopriv_wpbo_search_responseby_intent', 'qc_wpbo_search_responseby_intent');
