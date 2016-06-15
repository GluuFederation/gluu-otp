"""
This file contains the abstraction of the database.
"""
import yubistatus

from sql import connect_to_db, SQL
from ldapdriver import LDAPConnection


class Backend(object):

    __drivers = ['SQLITE', 'LDAP']

    def __init__(self, driver, uri=None, connection=None):  # FIXME ugly hack handling connection
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
            self.ldap = LDAPConnection(uri)

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
