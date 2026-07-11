<?php
// Positive — request id selects the deleted post, no capability check (IDOR / broken access control).
add_action('wp_ajax_nopriv_del', 'idor_del');
function idor_del() {
    $id = $_POST['post_id'];
    wp_delete_post($id, true);
}

// Positive — numeric coercion makes the id injection-safe but it is STILL the attacker's chosen resource
// selector, so IDOR persists (numeric sanitizer != authorization).
function idor_del_int() {
    wp_delete_post(intval($_GET['pid']));
}

// Positive — an is_numeric() VALIDATION guard likewise stops injection but not IDOR.
function idor_del_isnum() {
    if (is_numeric($_GET['pid'])) {
        wp_delete_post($_GET['pid']);
    }
}

// Negative — guarded by current_user_can (real authorization) in the same function.
function idor_del_guarded() {
    if (!current_user_can('delete_posts')) wp_die();
    wp_delete_post($_POST['post_id'], true);   // no finding
}
