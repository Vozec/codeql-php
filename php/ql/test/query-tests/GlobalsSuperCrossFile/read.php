<?php
function run() { system($GLOBALS['cfg']); }   // BUG: $GLOBALS superglobal is cross-file
