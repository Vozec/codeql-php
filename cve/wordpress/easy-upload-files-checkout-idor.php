<?php
// Easy Upload Files During Checkout <= 3.0.1 — unauthenticated arbitrary post/attachment deletion (IDOR /
// broken access control). ufdc_custom_init() runs on every visit; it deletes the object whose id comes
// straight from $_GET['eufdc-delete']. The only checks are is_numeric() (a VALIDATION guard — stops
// injection, not IDOR: the id is still attacker-chosen) and is_user_logged_in() (authentication, NOT
// authorization). There is no current_user_can() capability check, so any unauthenticated visitor can
// delete arbitrary posts/attachments by id. Faithful to inc/functions.php::ufdc_custom_init().
// Source: $_GET['eufdc-delete']. Sink: wp_delete_post / wp_delete_attachment (resource id, unguarded).
// Ref: patchstack.com — "Missing Authorization to Unauthenticated Arbitrary Attachment Deletion".
function ufdc_custom_init() {
    if (isset($_GET['eufdc-delete']) && is_numeric($_GET['eufdc-delete'])) {   // is_numeric != authorization
        $postid = sanitize_text_field($_GET['eufdc-delete']);
        if ($postid) {
            $user_id = 0;
            if (is_user_logged_in()) {                                          // authentication, not authz
                $user_id = wp_get_current_user()->ID;
            }
            // ruleid: php/idor
            wp_delete_post($postid, true);
            // ruleid: php/idor
            wp_delete_attachment($postid, true);
        }
    }
}
