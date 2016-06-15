"""
LDAP client application

- provides the fucntions to perform SEARCH, ADD and MODIFY operations
"""
import ldap

from ldap.filter import filter_format


class LDAPConnection(object):

    # FIXME Replace the base dn with the proper DN
    BASE_DN = 'ou=yubikeys,o=gluu'

    REQUESTS = {
        'yubico_get_key': '(publicname=%s)',
        }

    def __init__(self, uri, dn=None, pw=None):
        self.con = ldap.initialize(uri)
        # get the inumOrg and build the custom base_dn using the inumOrg
        # self.base_dn = "ou=otp_devices,o={0},o=gluu".format(inumOrg)

        if dn and pw:
            self.con.simple_bind_s(dn, pw)

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
                self.BASE_DN, ldap.SCOPE_SUBTREE, filts,
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
