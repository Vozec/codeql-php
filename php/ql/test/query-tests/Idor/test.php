<?php
// Positive — request id selects the deleted post, no capability check (IDOR / broken access control).
add_action('wp_ajax_nopriv_del', 'idor_del');
function idor_del() {
    $id = $_POST['post_id'];
    wp_delete_post($id, true);            // flagged: unguarded request-selected delete
}

// Negative — guarded by current_user_can in the same function.
function idor_del_guarded() {
    if (!current_user_can('delete_posts')) wp_die();
    wp_delete_post($_POST['post_id'], true);   // no finding
}
