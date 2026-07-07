<?php
system(getenv("TEMP"));         // NO flag — server var (line 2)
system(getenv("HTTP_HOST"));    // flag line 3 — user-controllable header
system(getenv($k));             // flag line 4 — dynamic key (conservative)
system(getenv("PATH"));         // NO flag — server var (line 5)
