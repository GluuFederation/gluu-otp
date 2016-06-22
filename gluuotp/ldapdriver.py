"""
LDAP client application

- provides the fucntions to perform SEARCH, ADD and MODIFY operations
"""
import ldap
import json

import config  # local config object

from ldap.filter import filter_format
from ldap.modlist import modifyModlist


class LDAPConnection(object):
    def __init__(self):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self.con = ldap.initialize(config.LDAP_URI)

        if config.LDAP_USER and config.LDAP_PASS:
            self.con.simple_bind_s(config.LDAP_USER, config.LDAP_PASS)

    def get_keys(self, username):
        """Function that searchs the LDAP for the user and returns user's
        gluuOTPMetadata (which is a list of keys stored for that person).

        Params:
            username (string) - The username (uid) of the user

        Returns:
            keys (list) - The data from gluuOTPMetadata field in the ldap
                which is a string of JSON containing the information about
                the Yubikey
        """
        filt = filter_format('(uid=%s)', [username])
        results = self.con.search_s(
                config.BASE_DN, ldap.SCOPE_SUBTREE, filt, []
                )
        if len(results) == 0:
            return None

        dn, user = results[0]
        return user['gluuOTPMetadata']

    def update_key(self, username, key):
        """Function that updates the particular key of the user.

        Params:
            username (string) - the user whose key is to be updated
            key (dict) - the key dict with updated values
        """
        filt = filter_format('(uid=%s)', [username])
        results = self.con.search_s(
                config.BASE_DN, ldap.SCOPE_SUBTREE, filt, []
                )
        if len(results) == 0:
            return

        dn, user = results[0]

        # A user might have multiple keys. Search and find the right key
        # and update with the new counter and timestamp value
        keys = user['gluuOTPMetadata']
        oldkey = None
        for k in keys:
            if key['publicname'] in k:
                oldkey = k

        if not oldkey:
            return

        mods = modifyModlist({'gluuOTPMetadata': oldkey},
                             {'gluuOTPMetadata': json.dumps(key)})

        self.con.modify_s(dn, mods)
