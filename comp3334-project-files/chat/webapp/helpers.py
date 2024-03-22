from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


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


