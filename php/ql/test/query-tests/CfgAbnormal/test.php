<?php
// Each abnormal producer is followed by a sibling statement that must be UNREACHABLE from it.

function f_return() {
    return;
    echo "dead after return";
}

function g_break($c) {
    while ($c) {
        break;
        echo "dead after break";
    }
}

function h_continue($c) {
    while ($c) {
        continue;
        echo "dead after continue";
    }
}

function i_throw() {
    throw new Exception("x");
    echo "dead after throw";
}

// nested: break inside an if inside a loop still cuts the following sibling
function j_nested($c, $d) {
    while ($c) {
        if ($d) {
            break;
            echo "dead after nested break";
        }
        echo "reachable";
    }
}
