#!/usr/bin/env python3
# -*- coding: utf-8 -*-

######################################################################
# cryptographypractice -- practice about symmetric ciphering and hash functions with
# the "cryptography" library
#
# Copyright (c) 2021, Scan0r
#
# This program is free software: you can redistribute it and/or modifyç
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# @Author       Scan0r
# @Date         22/11/2021
# @Version      0.1
######################################################################

# Global Imports
import random
import string
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


######################################################################
#
# Section 1
#
######################################################################

def get_cipher(key: str, iv: str, mode: str) -> Cipher:
    ''' Gets an instance of the Cipher class with the given ciphering parameters '''

    # Checks the number of required parameters
    if not key or not iv or not mode:
        raise Exception("empty key or IV or mode")

    # Checks the correct type of parameters
    if isinstance(key, str):
        key = key.encode()
    else:
        raise Exception("invalid type of key, must be a string")

    if isinstance(iv, str):
        iv = iv.encode()
    else:
        raise Exception("invalid type of IV, must be a string")

    if not isinstance(mode, str):
        raise Exception("invalid type of mode, must be a string")

    # Checks the length and validity of the IV
    if len(iv) != 16:
        raise Exception(
            f"the length of the initialization vector (IV) must be the same as the length of the block (16), given {len(iv)}")

    # Selects the ciphering mode
    mode = mode.upper()
    if mode == "CBC":
        mode_iv = modes.CBC(iv)
    elif mode == "OFB":
        mode_iv = modes.OFB(iv)
    elif mode == "CFB":
        mode_iv = modes.CFB(iv)
    elif mode == "ECB":
        mode_iv = modes.ECB()
    else:
        raise Exception(f"invalid cipher mode {mode}")

    # Returns the instance Checks the correct type of parameters
    return Cipher(algorithms.AES(key), mode_iv)


def encrypt(msg: str, key: str, iv: str, mode: str) -> bytes:
    ''' Encrypts a given message by the symmetric encryption AES, using a given key,
    a initialization vector and a encryption mode '''

    # Checks the validity of the required parameters
    if not isinstance(msg, str) or len(msg) == 0:
        raise Exception(
            "empty or invalid message, message must be a non-empty string")

    # Converts the text message to a bytes array
    msg = msg.encode()

    # Gets a cipher instance
    cipher = get_cipher(key, iv, mode)
    # Gets an encryptor instance
    encryptor = cipher.encryptor()
    # Encrypts the message
    encrypted_text = encryptor.update(msg) + encryptor.finalize()
    # Returns the encrypted message as a sequence of bytes
    return encrypted_text


def decrypt(msg: bytes, key: str, iv: str, mode: str) -> str:
    ''' Decrypts an encrypted given message by the symmetric encryption AES, using a
    given key, a initialization vector and encryption mode. '''

    # Checks the validity of the required parameters
    if not isinstance(msg, bytes) or len(msg) == 0:
        raise Exception(
            "empty or invalid message, message must be a non-empty bytes-like array")

    # Gests a cipher instance
    cipher = get_cipher(key, iv, mode)
    # Gets a decryptor instance
    decryptor = cipher.decryptor()
    # Decrypts the message
    decrypted_text = decryptor.update(msg) + decryptor.finalize()
    # Returns the decrypted messsage as a plain text string
    return decrypted_text.decode()


def cipher_decipher_text(msg: str, key: str, iv: str, mode: str):
    ''' Performs the encryption and decryption operations of a given message by the
    symmetric encryption AES, using a given key, an initialization vector and an encryption mode '''

    # Prints the value of the encryption and decryption parameters used
    print(f'[+] Symmetrical encryption and decryption using:')
    print(f' algorithm="AES"')
    print(f' message="{msg[0:75] + "..." if len(msg) > 75 else msg}"')
    print(f' key="{key[0:75] + "..." if len(key) > 75 else key}"')
    print(f' iv="{iv}"')
    print(f' mode="{mode}"')
    print()

    # Performs the encryption and decryption of the message
    encrypted_text = encrypt(msg, key, iv, mode)
    decrypted_text = decrypt(encrypted_text, key, iv, mode)

    # Beautifies the enrcrypted message from a sequence of bytes to hex format string
    encrypted_text_hex = "0x" + \
        "".join(list(map(hex, list(encrypted_text)))).replace("0x", "")

    # Prints the results
    print(f'Source text: "{msg}"')
    print(f'Encrypted text: {encrypted_text} == "{encrypted_text_hex}"')
    print(f'Decrypted text: "{decrypted_text}"')
    print("")


def cipher_decipher_text_ivs(ivs: List[str], msg: str, key: str, mode: str):
    ''' Performs the encryption and decryption operations of a given message by the
    symmetric encryption AES, using a given key, an array of severals initialization vectors
    and an encryption mode '''

    # Checks the correct type of parameters
    if not isinstance(ivs, list):
        raise Exception("param IVs should be an array of strings")

    # Performs the ciphering a deciphering operations for each of the IV given
    for iv in ivs:
        cipher_decipher_text(msg, key, iv, mode)


# Basic parameters
message = "a secret message"
key = "12345678901234567890123456789012"

# a)
print("\nApartado A)\n")

mode = "CBC"
iv = 'a' * 16

cipher_decipher_text(message, key, iv, "CBC")


# b.1)
print("\nApartado B.1)\n")

iv = 'a' * 16

cipher_decipher_text(message, key, iv, "OFB")
cipher_decipher_text(message, key, iv, "CFB")
cipher_decipher_text(message, key, iv, "ECB")


# b.2)
print("\nApartado B.2)\n")

# Generates equal IVs
iv1 = ["a"*16 for i in range(2)]
# Generates random IVs
iv2 = [''.join(random.choice(string.ascii_letters)
               for _ in range(16)) for i in range(2)]

# For every IV and mode performs a ciphering a deciphering operation to compare
for i in [iv1, iv2]:
    for m in ["CBC", "OFB", "CFB", "ECB"]:
        print(f"------------------------- BEGIN IV={i}, MODE={m}\n")
        cipher_decipher_text_ivs(i, message, key, m)
        print(f"------------------------- END IV={i}, MODE={m}\n")


######################################################################
#
# Section 2
#
######################################################################

def md5_file(file: str) -> str:
    ''' Performs MD5 ciphering of the content of a given file '''

    print(f'[+] Calculating MD5(file="{file}")')
    # Reads the file content as bytes
    with open(file, 'rb') as f:
        content = f.read()

    # Gets a md5 hash instance
    digest = hashes.Hash(hashes.MD5())
    # Sets the payload to hash
    digest.update(content)
    # Computes the md5 hash
    hash_bytes = digest.finalize()
    # Beautifies the hashed message from a sequence of bytes to hex format string
    hash_hex = "0x" + "".join(list(map(hex, list(hash_bytes)))).replace("0x", "")
    # Prints the hash of the file in both formats
    print(f'[!] Hash: {hash_bytes} == "{hash_hex}"\n')
    # Returns the md5 hash of the file in hex format
    return hash_hex


md5_file("WinMD5.exe")
md5_file("WinMD5_2.exe")
