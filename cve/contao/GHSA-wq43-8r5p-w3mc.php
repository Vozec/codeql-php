<?php
// GHSA-wq43-8r5p-w3mc — Contao <= 3.2.4 / 2.11.13 — PHP Object Injection via the deserialize() helper.
// Many back-end actions pass raw POST through Contao's global deserialize() helper, which calls
// unserialize() with no allowed_classes. The sink sits one function boundary BEHIND the wrapper —
// the call sites contain no unserialize() at all, so only inter-procedural tracking connects them.
// Source: Input::post('IDS') (class-qualified static request accessor). Sink: unserialize() (arg -1).
// Flow: DC_Table::__construct -> deserialize -> unserialize.
// Ref: https://github.com/contao/core/commit/d67c46c (contao/core #6695)

class DC_Table {
    private $ids;

    public function __construct() {
        $this->ids = deserialize(Input::post('IDS'));   // user input through the wrapper
    }
}

// Contao system/helper/functions.php — the global (de)serialize helper every call site funnels through.
function deserialize($varValue, $blnForceArray = false) {
    // ruleid: php/unsafe-deserialization
    $varUnserialized = @unserialize($varValue);          // no allowed_classes => object injection
    return $varUnserialized;
}
