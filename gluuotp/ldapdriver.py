"""
LDAP client application

- provides the fucntions to perform SEARCH, ADD and MODIFY operations
"""
import ldap
import config  # local config object

from ldap.filter import filter_format


class LDAPConnection(object):

    REQUESTS = {
        'yubico_get_key': '(publicname=%s)',
        'get_keys': '(uid=%s)',
        }

    def __init__(self):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self.con = ldap.initialize(config.LDAP_URI)

        if config.LDAP_USER and config.LDAP_PASS:
            self.con.simple_bind_s(config.LDAP_USER, config.LDAP_PASS)

    def search(self, req, filters):
        """Returns the search results of the LDAP server.

        Params:
            req (string) - any one of the REQUESTS
            filters (list) - list of the filter params for the REQ string

        Returns:
            results (list) - a list of tuples in the format (dn, dict(attrs))
        """
        filts = filter_format(self.REQUESTS[req], filters)
        results = self.con.search_s(
                config.BASE_DN, ldap.SCOPE_SUBTREE, filts,
                [])  # retrives all attributes since list is empty

        return results

    def update(self, dn, attr, value):
        """Updates the attribute with the new value for the mentioned DN.

        Params:
            dn (string) - the dn value of the entry
            attr (string) - the attribute that is to be updated
            value (string) - the new value to replace the old one
        """
        modlist = [(ldap.MOD_REPLACE, attr, value)]
        self.con.modify_s(dn, modlist)

    def update_d(self, dn, d):
        """Similar to `update`, but performs multiple updations using dict.

        Params:
            dn (string) - the dn of the entry
            d (dict)    - the dictionary containing the attributes and their
                corresponding new values
        """
        modlist = []
        for k, v in d.items():
            modlist.append((ldap.MOD_REPLACE, k, v))
        self.con.modify_s(dn, modlist)
