# Gluu OTP

Gluu OTP is a YubiKey Validation Library, written in Python, which is bundled with the Gluu Server.

## Developement

### Pre-requisites

```
apt-get install python-pip python-dev libsasl2-dev python-dev libldap2-dev libssl-dev
pip install -r requirements.txt
```

* Copy the file `gluuotp/config.py.sample` to `gluuotp/config.py` and edit the file to put in your ldap credentials as required.

## Run a HTTP Validation server

```
apt-get install python-crypto python-ldap
python gluuotp/yubiserve.py
```

Visit `http://localhost:8000`

## Attributions

This is a fork of the project [Yubikeyedup](https://github.com/scumjr/yubikeyedup) by [@scumjr](https://github.com/scumjr), which in turn is a fork of YubiServe has been written by Alessio Periloso \<mail *at* periloso.it\>. The READMEs of the original projects can be found in the files `README.old` and `README.old.1`.

This fork adds customizations required for Gluu Server.
