<?php
// XPath injection: user input concatenated into an XPath expression is a sink; a constant expression
// is not. SimpleXMLElement::xpath is matched by name; DOMXPath::query/evaluate are class-scoped.
function search(SimpleXMLElement $xml) {
    $user = $_GET['q'];
    return $xml->xpath("//user[name='" . $user . "']");        // BUG: SimpleXMLElement::xpath
}

function domsearch(DOMXPath $xpath) {
    $user = $_GET['q'];
    return $xpath->query("//user[name='" . $user . "']");      // BUG: DOMXPath::query
}

function safe(SimpleXMLElement $xml) {
    return $xml->xpath("//user[active='1']");                  // safe: constant expression, no taint
}
