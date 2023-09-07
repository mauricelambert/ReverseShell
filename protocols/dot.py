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

from .dns import DNS


class DOT(DNS):
    """
    This class parses and writes DNS over TCP request and response.
    """

    def __init__(self):
        self.dns_id = b"\x33\x66"

    def parse(self, data: bytes) -> bytes:
        """
        This method parses DNS over TCP query and response.
        """

        return super().parse(data[2:])

    parse_request = parse
    parse_response = parse

    def tcp_wrapper(self, data: bytes) -> bytes:
        """
        This method wraps DNS packets (queries and answers) to DNS over TCP.
        """

        data_length = len(data)
        return (
            data_length.to_bytes(2) if data_length < 65535 else b"\xff\xff"
        ) + data

    def wrap_response(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS over TCP response to
        hide ReverseShell payload in DNS traffic.
        """

        return self.tcp_wrapper(super().wrap_response(data))

    def wrap_request(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS over TCP query to hide
        ReverseShell response in HTTP traffic.
        """

        return self.tcp_wrapper(super().wrap_request(data))
