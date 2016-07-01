# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan, Arunmozhi
#

from org.jboss.seam.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import UserService
from org.xdi.util import StringHelper

import java

import httplib
import urllib
import uuid


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Yubicloud. Initialization"
        print "Yubicloud. Initialized successfully"

        self.api_server = configurationAttributes.get("yubicloud_uri").getValue2()
        self.api_key = configurationAttributes.get("yubicloud_api_key").getValue2()
        self.client_id = configurationAttributes.get("yubicloud_id").getValue2()

        return True

    def destroy(self, configurationAttributes):
        print "Yubicloud. Destroy"
        print "Yubicloud. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Yubicloud. Authenticate for step 1"

            credentials = Identity.instance().getCredentials()
            username = credentials.getUsername()
            otp = credentials.getPassword()

            # Validate otp length
            if len(otp) < 32 or len(otp) > 48:
                return False

            user_service = UserService.instance()
            user = user_service.getUser(username)

            public_key = user.getAttribute('yubikeyId')

            # Match the user with the yubikey
            if public_key not in otp:
                return False

            nonce = uuid.uuid4().replace("-", "")
            params = urllib.urlencode({"id": self.client_id, "otp": otp, "nonce": nonce})
            con = httplib.HTTPSConnection(self.yubicloud_uri)
            con.request("GET", "/wsapi/2.0/verify/?"+params)
            response = con.getresponse()
            data = response.read()

            if "status=OK" not in data:
                return False

            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Yubicloud. Prepare for Step 1"
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
