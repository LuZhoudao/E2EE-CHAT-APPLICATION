from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import onetimepass as otp
from wtforms import StringField
from wtforms.validators import DataRequired

# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def AESencrypt(cipher, plaintext):
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct


def AESdecrypt(key, iv, ct):
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt


def get_totp_uri(username, totp_secret):
    return f'otpauth://totp/TOTPDemo:{username}?secret={totp_secret}&issuer=TOTPDemo'


def verify_totp(totp_secret):
    return otp.valid_totp(StringField('Token', validators=[DataRequired()]), totp_secret)