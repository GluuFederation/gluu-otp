# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan, Arunmozhi
#

from org.jboss.seam.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType

from gluuotp.validate import Validate


class PersonAuthentication(PersonAuthenticationType):
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

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "GluuOTP Authenticate for step 1"

            credentials = Identity.instance().getCredentials()
            user_name = credentials.getUsername()
            otp = credentials.getPassword()  # this should be the Yubikey OTP

            if not(user_name and otp):
                return False

            validator = Validate()
            result = validator.validate_user(user_name, otp)

            if result == 'OK':
                return True

            print result
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
