"""
This file contains the abstraction of the database.
"""
import yubistatus

from sql import connect_to_db, SQL
from ldapdriver import LDAPConnection


class Backend(object):

    __drivers = ['SQLITE', 'LDAP']

    def __init__(self, driver, uri=None, connection=None):  # FIXME ugly hack
        """Initializing function

        driver (string) - either 'SQLITE' or 'LDAP'
        uri (string) - OPTIONAL The location of the SQLITE databse file or the
            LDAP uri
        connection (object) - OPTIONAL SQL Connection
        """
        self.driver = driver
        if driver not in self.__drivers:
            self.driver = 'SQLITE'

        if self.driver == 'SQLITE' and not connection:
            sql_connection = connect_to_db(uri)
            self.sql = SQL(sql_connection)
        elif self.driver == 'SQLITE' and connection:
            self.sql = connection
        elif self.driver == 'LDAP':
            self.ldap = LDAPConnection()

    def get_key(self, userid):
        """Function that fetches the aeskey, internalname, counter and timestamp
        from the data storage.

        Params:
            userid (string)  - the userid (keyid) extracted from the OTP

        Returns:
            key (tuple) - (aeskey, internalname, counter, time) if the supplied
                userid matches an entry in the Data Storage
        """
        if self.driver == 'SQLITE':
            if not self.sql.select('yubico_get_key', [userid]):
                return yubistatus.BAD_OTP
            aeskey, internalname, counter, time = self.sql.result
        elif self.driver == 'LDAP':
            dn, entry = self.ldap.search('yubico_get_key', [userid])[0]
            aeskey = entry['aeskey'][0]
            internalname = entry['internalname'][0]
            counter = int(entry['counter'][0])
            time = int(entry['time'][0])

        return (aeskey, internalname, counter, time)

    def update_counter(self, count, timestamp, userid):
        """Function that updates the counter in the data.

        Params:
            count (int) - the new count to updated
            timestamp (int) - the timestamp from the otp
            userid (string) - the userid for the key for which the counter has
                to be updated.
        """
        if self.driver == 'SQLITE':
            self.sql.update('yubico_update_counter',
                            [count, timestamp, userid])
        elif self.driver == 'LDAP':
            dn, entry = self.ldap.search('yubico_get_key', [userid])[0]
            self.ldap.update_d(dn, {'counter': str(count),
                                    'time': str(timestamp)})

    def get_user_keys(self, username):
        """LDAP only function that retrieves the keys of a user.

        Params:
            username (string) - the uid of the user in ldap
        """
        if self.driver == 'LDAP':
            dn, entry = self.ldap.search('get_keys', username)
            return entry['gluuOTPMetadata']

    def update_key(self, username, key):
        """LDAP only function that updates the particular key of the user.

        Params:
            username (string) - the user whose key is to be updated
            key (string) - the key dict as string with updated values
        """
        dn, entry = self.ldap.search('get_keys', username)
        # NOTE This way of updating restricts to one OTP key per person
        self.ldap.update(dn, 'gluuOTPMetadata', key)
