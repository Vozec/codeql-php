<?php
// POSITIVE 1 — user input stored via update_option, later unserialized (object injection).
function save_poi() {
    update_option('poi_key', $_POST['payload']);
}
function load_poi() {
    return unserialize(get_option('poi_key'));            // $ hasStoredInjection
}

// POSITIVE 2 — user input stored via post_meta, later rendered by Twig (SSTI).
function save_tpl() {
    update_post_meta(1, 'tpl_key', $_REQUEST['t']);
}
function render_tpl($twig) {
    return $twig->render(get_post_meta(1, 'tpl_key', true));   // $ hasStoredInjection
}

// NEGATIVE 1 (guard) — key is NEVER written anywhere: not a source, must NOT flag.
function load_unwritten() {
    return unserialize(get_option('never_written_key'));
}

// NEGATIVE 2 (guard) — key IS written but from a constant, not user input: must NOT flag.
function save_const() {
    update_option('const_key', 'a static safe value');
}
function load_const() {
    return unserialize(get_option('const_key'));
}
