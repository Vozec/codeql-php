<?php
// A `posts_where` filter callback's RETURN string is concatenated into SQL by WP_Query, so a tainted
// return (request input built into the clause) is SQL injection; a constant/untainted return is not.
function register_unsafe() {
    add_filter('posts_where', function ($where) {
        $s = sanitize_text_field($_REQUEST['search']);
        return $where . " AND post_title LIKE '%" . $s . "%'";   // BUG: tainted return -> WP_Query SQL
    });
}

function register_safe() {
    add_filter('posts_where', function ($where) {
        return $where . " AND post_status = 'publish'";          // safe: constant return, no taint
    });
}
