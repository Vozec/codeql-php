<?php
// phpLDAPadmin — LDAP injection via the login username (exploit-db 44926, class documented for 1.2.x).
// getLoginID() builds the authentication search filter with sprintf('(&(%s=%s)...)', $attr, $user) where
// $user is the login-form username, with NO ldap_escape() — so a crafted username (e.g. `*)(uid=*` )
// injects into the LDAP filter, which query()/run() hand to ldap_search(). Authentication-bypass / data
// disclosure. Faithful to lib/ds_ldap.php::getLoginID() + the query()->ldap_search() path.
// Source: login username ($_POST['login']). Sink: ldap_search() (filter arg). Inter-procedural via query().
// Ref: https://www.exploit-db.com/exploits/44926
class ds_ldap {
    private $resource;
    private $base = 'dc=example,dc=com';

    // lib/ds_ldap.php:525 — builds the login search filter from the untrusted username, then runs it via
    // query() -> ldap_search() (lib/ds_ldap.php:428). The query() indirection is collapsed here; its only
    // relevant effect is handing $query['filter'] to ldap_search unchanged.
    public function getLoginID($user) {
        $query = array();
        $query['filter'] = sprintf('(&(%s=%s))', 'uid', $user);   // $user unescaped in the LDAP filter
        $query['base'] = $this->base;
        // ruleid: php/ldap-injection
        $search = @ldap_search($this->resource, $query['base'], $query['filter']);
        return ldap_get_entries($this->resource, $search);
    }
}

// login handler: the posted username feeds the auth search.
$ds = new ds_ldap();
$ds->getLoginID($_POST['login']);
