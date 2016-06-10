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

    def __init__(self, driver, uri=None, connection=None):  # FIXME ugly hack handling connection
        """Initializing function

        driver (string) - either 'SQLITE' or 'LDAP'
        uri (string) - OPTIONAL The location of the SQLITE databse file or the LDAP uri
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

    def update_counter(self, count, timestamp, userid):
        """Function that updates the counter in the data.

        Params:
            count (int) - the new count to updated
            timestamp (int) - the timestamp from the otp
            userid (string) - the userid for the key for which the counter has
                to be updated.

        Returns:
            status (bool) - the success status of the update operation
        """
        if self.driver == 'SQLITE':
            self.sql.update('yubico_update_counter',
                            [count, timestamp, userid])
            return True
