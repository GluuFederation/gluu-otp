import re
import json

import status

from Crypto.Cipher import AES

from ldapdriver import LDAPConnection


class Validate(object):

    # sorry for this one-liner
    modhex = ''.join(dict([('cbdefghijklnrtuv'[i], '0123456789abcdef'[i])
                     for i in range(16)]).get(chr(j), '?') for j in range(256))

    def __init__(self):
        self.ldap = LDAPConnection()

    def modhexdecode(self, string):
        return string.translate(self.modhex).decode('hex')

    def CRC(self, data):
        crc = 0xffff
        for b in data:
            crc ^= (ord(b) & 0xff)
            for j in range(0, 8):
                n = crc & 1
                crc >>= 1
                if n != 0:
                    crc ^= 0x8408
        return crc

    def validate_user(self, username, otp):
        """Validates the OTP of the requested user.

        This function is written specifically to address the requirement of
        username in order to fetch the gluuOTPMetadata fromt he LDAP server.
        This has no particular use when using a RDBMS like SQLITE.

        The format for gluuOTPMetadata is a <string> of the following JSON
        {
            'publicname': 'string',
            'internalname': 'string',
            'aeskey': 'string',
            'counter': int,
            'time': int
        }

        Params:
            username (string) - the username stored in the ldap
            otp (string) - the otp by the yubikey
        """
        match = re.match('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})',
                         otp)
        if not match:
            return status.BAD_OTP

        public_name, token = match.groups()

        keys = self.ldap.get_keys(username)
        # the user doesn't have any Yubikeys registered against his name
        if not keys:
            return status.UNREGISTERED_KEY

        key_data = None
        for key in keys:
            if public_name in key:
                key_data = key

        # None of the user's keys match the OTP key
        if not key_data:
            return status.UNREGISTERED_KEY

        key = json.loads(key_data)
        aeskey = key['aeskey']
        internalname = key['internalname']
        counter = key['counter']
        time = key['time']

        aes = AES.new(aeskey.decode('hex'), AES.MODE_ECB)
        plaintext = aes.decrypt(self.modhexdecode(token)).encode('hex')

        if internalname != plaintext[:12]:
            return status.BAD_OTP

        if self.CRC(plaintext[:32].decode('hex')) != 0xf0b8:
            return status.BAD_OTP

        internalcounter = int(plaintext[14:16] + plaintext[12:14] +
                              plaintext[22:24], 16)
        if counter >= internalcounter:
            return status.REPLAYED_OTP

        timestamp = int(plaintext[20:22] + plaintext[18:20] + plaintext[16:18],
                        16)
        if time >= timestamp and (counter >> 8) == (internalcounter >> 8):
            return status.BAD_OTP

        # IMPORTANT: Updating with the counter and time is important to avoid
        #            reuse of OTPs
        key['counter'] = internalcounter
        key['time'] = timestamp
        self.ldap.update_key(username, key)

        return status.OK
