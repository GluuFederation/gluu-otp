import re
import json

from Crypto.Cipher import AES

from backend import Backend
import status


class Validate:
    def __init__(self, backend):
        if backend == 'SQLITE':
            self.backend = Backend('SQLITE', 'yubikeys.sqlite')
        elif backend == 'LDAP':
            self.backend = Backend('LDAP')


class YubicoOTP(Validate):
    # sorry for this one-liner
    modhex = ''.join(dict([('cbdefghijklnrtuv'[i], '0123456789abcdef'[i])
                     for i in range(16)]).get(chr(j), '?') for j in range(256))

    def set_params(self, params, answer):
        if 'nonce' not in params:
            return status.MISSING_PARAMETER

        answer['otp'] = params['otp']
        answer['nonce'] = params['nonce']
        answer['sl'] = '100'

        self.otp = params['otp']

        return status.OK

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

    def validate(self, otp=None):
        if otp:
            self.otp = otp

        match = re.match('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})',
                         self.otp)
        if not match:
            # this should not happen because otp matches
            # YubiHTTPServer.PARAM_REGEXP
            return status.BAD_OTP

        userid, token = match.groups()

        key_data = self.backend.get_key(userid)
        if not key_data:
            return status.BAD_OTP
        aeskey, internalname, counter, time = key_data

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

        self.backend.update_counter(internalcounter, timestamp, userid)

        return status.OK

    def validate_user(self, username, otp):
        """Validates the OTP of the requested user.

        This function is written specifically to address the requirement of
        username in order to fetch the gluuOTPMetadata fromt he LDAP server.
        This has no particular use when using a RDBMS like SQLITE.

        Params:
            username (string) - the username stored in the ldap
            otp (string) - the otp by the yubikey
        """
        if not otp:
            return status.BAD_OTP

        match = re.match('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})',
                         otp)
        if not match:
            return status.BAD_OTP

        public_name, token = match.groups()

        keys = self.backend.get_user_keys(username)

        key_data = None
        for key in keys:
            if public_name in key:
                key_data = key

        if not key_data:
            return status.BAD_OTP

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

        key['counter'] = internalcounter
        key['time'] = timestamp

        self.backend.update_key(username, key)

        return status.OK



class OATH(Validate):
    def set_params(self, params, answer):
        if len(otp) in [ 18, 20 ]:
            publicid = otp[0:12]
            oath = params['otp'][12:]
        elif len(otp) in [ 6, 8 ]:
            if not params.has_key('publicid'):
                return status.MISSING_PARAMETER
            publicid = params['publicid']
            oath = params['otp']
        else:
            return status.BAD_OTP

        answer['otp'] = params['otp']

        self.oath = oath
        self.publicid = publicid

        return status.OK

    def test_hotp(self, key, counter, digits=6):
        counter = str(counter).rjust(16, '0').decode('hex')
        hs = hmac.new(key, counter, hashlib.sha1).digest()
        offset = ord(hs[19]) & 0xF
        bin_code = int((chr(ord(hs[offset]) & 0x7F) + hs[offset+1:offset+4]).encode('hex'), 16)
        return str(bin_code)[-digits:]

    def validate(self):
        # XXX: TODO, it hasn't been tested
        return status.BACKEND_ERROR

        if len(self.oath) % 2 != 0:
            return status.BAD_OTP

        if not self.sql.select('oath_get_token', [publicid]):
            return status.BAD_OTP

        actualcounter, key = self.sql.result
        key = key.decode('hex')
        for counter in range(actualcounter + 1, actualcounter + 256):
            if self.oath == self.test_hotp(key, counter, len(self.oath)):
                self.sql.update('yubico_update_counter', [str(counter), self.publicid])
                return status.OK

        return status.BAD_OTP
