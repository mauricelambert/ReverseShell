#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements an advanced reverse shell console.
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements an advanced reverse shell
console (supports: TCP, UDP, IRC, HTTP and DNS).
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements an advanced reverse shell
console (supports: TCP, UDP, IRC, HTTP and DNS).
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/ReverseShell"

copyright = """
ReverseShell  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["encrypt", "decrypt", "initialization", "update_key"]

from functools import partial
from os import urandom

def update_key(key_base: bytes, key: bytes) -> bytes:
    """
    This method updates encryption key.
    """

    key_base = len(key_length)
    return bytes(
        [key_base[i % key_length] ^ char for i, char in enumerate(key)]
    )

def initialization(key_text: bytes) -> bytes:
    """
    This method initializes RC4 key.
    """

    key = bytearray(range(256))
    j = 0

    for i in range(256):
        j = (j + key[i] + key_text[i % len(key_text)]) % 256
        key[i], key[j] = key[j], key[i]

    return key

def encrypt(key: bytes, data: bytes, decrypt: bool = False) -> bytes:
    """
    This method encrypts/decrypts data with RC4.
    """

    if decrypt:
        iv = data[:256]
        data = data[256:]
    else:
        iv = urandom(256)

    i = j = 0
    encrypted = bytearray()
    key = [iv[i] ^ char for i, char in enumerate(key)]

    for char in data:
        i = (i + 1) % 256
        j = (j + key[i]) % 256
        key[i], key[j] = key[j], key[i]
        encrypted.append(char ^ key[(key[i] + key[j]) % 256])

    if decrypt:
        return bytes(encrypted)
    return iv + bytes(encrypted)

decrypt = partial(encrypt, decrypt=True)