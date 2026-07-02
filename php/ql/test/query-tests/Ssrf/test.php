<?php
curl_setopt($ch, CURLOPT_URL, $_GET['url']);  // BUG
fsockopen($_POST['host'], 80);                // BUG
curl_setopt($ch, CURLOPT_URL, "https://api"); // ok: constant
