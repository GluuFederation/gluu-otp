# Gluu OTP

Gluu OTP is a YubiKey Validation Server which is bundled as an optional component of the Gluu Server.

## Pre-requisites

```
apt-get install python-pip python-dev libsasl2-dev python-dev libldap2-dev libssl-dev
pip install -r requirements.txt
```

## Run the server

```
python gluuotp/yubiserve.py
```

## Attributions

This is a fork of the project [Yubikeyedup](https://github.com/scumjr/yubikeyedup) by [@scumjr](https://github.com/scumjr), which in turn is a fork of YubiServe has been written by Alessio Periloso \<mail *at* periloso.it\>. The READMEs of the original projects can be found in the files `README.old` and `README.old.1`.

This fork adds customizations required for Gluu Server.
