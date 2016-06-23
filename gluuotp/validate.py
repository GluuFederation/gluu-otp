import re

from Crypto.Cipher import AES

OK = 'OK'
BAD_OTP = 'BAD_OTP'
REPLAYED_OTP = 'REPLAYED_OTP'

# sorry for this one-liner
modhex = ''.join(dict([('cbdefghijklnrtuv'[i], '0123456789abcdef'[i])
                 for i in range(16)]).get(chr(j), '?') for j in range(256))


def modhexdecode(string):
    return string.translate(modhex).decode('hex')


def CRC(data):
    crc = 0xffff
    for b in data:
        crc ^= (ord(b) & 0xff)
        for j in range(0, 8):
            n = crc & 1
            crc >>= 1
            if n != 0:
                crc ^= 0x8408
    return crc


def validate(otp, internalname, aeskey, counter, time):
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
        return BAD_OTP

    public_name, token = match.groups()

    aes = AES.new(aeskey.decode('hex'), AES.MODE_ECB)
    plaintext = aes.decrypt(modhexdecode(token)).encode('hex')

    if internalname != plaintext[:12]:
        return BAD_OTP

    if CRC(plaintext[:32].decode('hex')) != 0xf0b8:
        return BAD_OTP

    internalcounter = int(plaintext[14:16] + plaintext[12:14] +
                          plaintext[22:24], 16)
    if counter >= internalcounter:
        return REPLAYED_OTP

    timestamp = int(plaintext[20:22] + plaintext[18:20] + plaintext[16:18],
                    16)
    if time >= timestamp and (counter >> 8) == (internalcounter >> 8):
        return BAD_OTP

    return OK
