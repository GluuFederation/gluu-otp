# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan, Arunmozhi
#

from org.jboss.seam.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import UserService

import re

from Crypto.Cipher import AES


class PersonAuthentication(PersonAuthenticationType):

    modhex = ''.join(dict([('cbdefghijklnrtuv'[i], '0123456789abcdef'[i])
                     for i in range(16)]).get(chr(j), '?') for j in range(256))

    OK = 'OK'
    BAD_OTP = 'BAD_OTP'
    REPLAYED_OTP = 'REPLAYED_OTP'

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "GluuOTP. Initialization"
        print "GluuOTP. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "GluuOTP. Destroy"
        print "GluuOTP. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType,
                                           configurationAttributes):
        return None

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

    def validate(self, otp, internalname, aeskey, counter, time):
        """Validates the OTP.

        Params:
            otp (string) - The otp string
            internalname (string) - the internal name of the Yubikey
            aeskey (string) - the aes key of the Yubikey
            counter (int) - the value of counter stored in DB
            time (int) - the timestamp of last used otp stored in DB

        Returns:
            status (string) - status of the evaluation
       """
        match = re.match('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})',
                         otp)
        if not match:
            return self.BAD_OTP

        public_name, token = match.groups()

        aes = AES.new(aeskey.decode('hex'), AES.MODE_ECB)
        plaintext = aes.decrypt(self.modhexdecode(token)).encode('hex')

        if internalname != plaintext[:12]:
            return self.BAD_OTP

        if self.CRC(plaintext[:32].decode('hex')) != 0xf0b8:
            return self.BAD_OTP

        internalcounter = int(plaintext[14:16] + plaintext[12:14] +
                              plaintext[22:24], 16)
        if counter >= internalcounter:
            return self.REPLAYED_OTP

        timestamp = int(plaintext[20:22] + plaintext[18:20] + plaintext[16:18],
                        16)
        if time >= timestamp and (counter >> 8) == (internalcounter >> 8):
            return self.BAD_OTP

        return self.OK

    def authenticate(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "GluuOTP Authenticate for step 1"

            credentials = Identity.instance().getCredentials()
            user_name = credentials.getUsername()
            otp = credentials.getPassword()  # this should be the Yubikey OTP

            if not(user_name and otp):
                return False

            userService = UserService.instance()
            user = userService.getUser(user_name)

            if not user:
                print "GluuOTP. Failed to find the user with ID: %s" % (user_name)
                return False

            gluuOTPMetadata = user.getAttribute('gluuOTPMetadata')
            print "GluuOTP Metadata: %s" % (str(gluuOTPMetadata))
            return True

        return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "GluuOTP. Prepare for Step 1"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return ""

    def logout(self, configurationAttributes, requestParameters):
        return True
