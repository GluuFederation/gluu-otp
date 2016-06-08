"""
This file should contain the abstraction of the database.

This should provide mere get and set functions for the data used by the various
functions of the application.

The object should be initialized using the driver name SQL/LDAP.
NOTE: It is ok to hard code somethings of the LDAP config/schema for the initial version.

"""
import yubistatus

from sql import connect_to_db, SQL


class Backend(object):

    __drivers = ['SQLITE', 'LDAP']

    def __init__(self, driver, uri):
        """Initializing function

        driver (string) - either 'SQLITE' or 'LDAP'
        uri (string) - The location of the SQLITE databse file or the LDAP uri
        """
        self.driver = driver
        if driver not in self.__drivers:
            self.driver = 'SQLITE'

        if self.driver == 'SQLITE':
            sql_connection = connect_to_db(uri)
            self.sql = SQL(sql_connection)

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
        else:
            # TODO get the following from LDAP
            aeskey = ''
            internalname = ''
            counter = ''
            time = ''

        return (aeskey, internalname, counter, time)
