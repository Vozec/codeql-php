<?php
// A custom no-op that SHADOWS a modeled sanitizer name must NOT be trusted — its real (empty) body is
// analysed, so taint still flows and the XSS is reported. (User's point: a name-only sanitizer model is
// a false-negative trap.)
function sanitize_text_field($x) { return $x; }       // no-op, same name as the WP core sanitizer
$v = sanitize_text_field($_GET['x']);
echo $v;                                                // WANT reflected XSS (line 7) — NOT suppressed

// Control: a REAL external escaper (esc_html — not defined in this file) DOES sanitize.
echo esc_html($_GET['y']);                              // must NOT flow (line 10)
