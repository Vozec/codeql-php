<?php
header("Location: " . $_GET['url']);    // BUG
header("Location: /home");              // ok: constant
