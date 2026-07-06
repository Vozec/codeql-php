<?php
// Arbitrary file read via user input (PHP filter chains). Source $_POST, path-traversal sinks.
readfile($_POST[0]);                                    // WANT line 3
getimagesize($_POST[0]);                                // WANT line 4
md5_file($_POST[0]);                                    // WANT line 5
sha1_file($_POST[0]);                                   // WANT line 6
hash_file('md5', $_POST[0]);                            // WANT line 7
file($_POST[0]);                                        // WANT line 8
parse_ini_file($_POST[0]);                              // WANT line 9
copy($_POST[0], '/tmp/test');                           // WANT line 10
$f1 = new finfo(); $f1->file($_POST[0], FILEINFO_MIME); // WANT line 11
$fp = fopen($_POST[0], "r");                            // WANT line 12 (fopen is the sink)
$fp2 = fopen($_POST[0], "r"); stream_get_contents($fp2); // WANT line 13 (fopen)
mime_content_type($_POST[0]);                           // WANT line 14
highlight_file($_POST[0]);                              // WANT line 15
new SplFileObject($_POST[0]);                           // WANT line 16
