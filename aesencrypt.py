# Authors: Filippo Dolente & Angelo Carbone
# 2020-12-05
# ver 1.1

# Module for encryption management

# *----------------import---------------*#

import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

# *----------------Global Variables and Constants---------------*#

# AES supports multiple key sizes: 16 (AES128), 24 (AES192), or 32 (AES256).
key_bytes = 32

# *----------------Functions---------------*#


def encrypt(key, plaintext, iv):
    """Takes as input a 32-byte key, the IV and an arbitrary-length plaintext.
    Returns a ciphtertext.
    "iv" stands for initialization vector."""

    # Check key length
    assert len(key) == key_bytes

    # Convert the IV to a Python integer.
    iv_int = int(binascii.hexlify(iv), 16)

    # Create a new Counter object with IV = iv_int.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt and return ciphertext.
    ciphertext = aes.encrypt(plaintext.encode("utf8"))

    return ciphertext


def decrypt(key, iv, ciphertext):
    """Takes as input a 32-byte key, the IV and an arbitrary-length chipertext.
    Returns a plaintext."""

    assert len(key) == key_bytes
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = aes.decrypt(ciphertext)

    return plaintext.decode()
