<?php
// Positive — unauthenticated AJAX deletes a post with no capability check.
add_action('wp_ajax_nopriv_del', 'ac_del');
function ac_del() {
    wp_delete_post((int) $_POST['id'], true);   // $ MissingAuthorization
}

// Negative — guarded by current_user_can.
add_action('wp_ajax_nopriv_del2', 'ac_del_safe');
function ac_del_safe() {
    if (!current_user_can('delete_posts')) wp_die();
    wp_delete_post((int) $_POST['id'], true);    // no finding
}

// Positive — authenticated AJAX writes an option, unguarded.
add_action('wp_ajax_opt', 'ac_opt');
function ac_opt() {
    update_option('setting', $_POST['v']);       // $ MissingAuthorization
}

// Positive — PrestaShop ajaxProcess convention entrypoint, unguarded settings write.
class AcCtrl {
    public function ajaxProcessNuke() {
        Configuration::updateValue('PS_SHOP_ENABLE', 0);  // $ MissingAuthorization
    }
    public function ajaxProcessSafe() {
        if (!$this->access('edit')) return;
        Configuration::updateValue('PS_X', 1);            // no finding (guarded)
    }
}
