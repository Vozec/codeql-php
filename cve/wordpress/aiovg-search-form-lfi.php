<?php
// All-in-One Video Gallery <= 3.6.5 — authenticated (Contributor+) LFI via the aiovg_search_form shortcode.
// [aiovg_search_form template="X"] — the `template` attribute is concatenated into an include() path with
// no whitelist/basename, so template=../../../wp-config includes an arbitrary file. Faithful to the real
// code (public/search.php: a class registers the shortcode via array($this, 'method')).
// Source: shortcode `template` attribute (add_shortcode callback). Sink: include (file inclusion).
// Flow: run_shortcode_search_form ($atts['template']) -> include.
// Ref: https://wpscan.com/plugin/all-in-one-video-gallery/ (< 3.7.0, aiovg_search_form LFI, no CVE assigned);
//      plugins.svn.wordpress.org/all-in-one-video-gallery/tags/3.6.5/public/search.php
class AIOVG_Public_Search {
    public function __construct() {
        add_shortcode('aiovg_search_form', array($this, 'run_shortcode_search_form'));
    }

    public function run_shortcode_search_form($atts) {
        // ruleid: php/file-inclusion
        include AIOVG_PLUGIN_DIR . 'public/templates/search-form-template-' . $atts['template'] . '.php';
    }
}
