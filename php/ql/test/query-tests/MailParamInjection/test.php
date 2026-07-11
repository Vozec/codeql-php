<?php
// mail()'s 5th argument (additional_parameters, index 4) is appended to the sendmail command line, so a
// tainted value is OS command injection. A tainted message body (arg 2) is NOT this sink.
function send_with_envelope($to) {
    $from = $_GET['from'];
    return mail($to, 'subject', 'body', 'From: x@y.z', '-f' . $from);   // BUG: arg 4 -> sendmail command line
}

function send_body() {
    $body = $_GET['msg'];
    return mail('a@b.c', 'subject', $body, 'From: x@y.z', '-fa@b.c');    // safe: tainted body (arg 2) is not the sink
}
