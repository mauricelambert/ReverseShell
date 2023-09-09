#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    TCP utils function for ReverseShell.
#    Copyright (C) 2023  ReverseShell

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
TCP utils function for ReverseShell.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
TCP utils function for ReverseShell.
"""
__url__ = "https://github.com/mauricelambert/ReverseShell"

__all__ = ["receiveall", "sendall"]

__license__ = "GPL-3.0 License"
__copyright__ = """
ReverseShell  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from ssl import SSLWantReadError
from socket import socket

def receiveall(socket: socket, timeout: bool = True) -> bytes:
    """
    This method gets all packets sent.
    """

    new = data = socket.recv(65535)
    socket.settimeout(0.5) if timeout else socket.setblocking(False)

    while new:
        try:
            new = socket.recv(65535)
            data += new
        except (BlockingIOError, SSLWantReadError, TimeoutError):
            break

    socket.setblocking(True)
    return data

def sendall(socket: socket, data: bytes, timeout: bool = True) -> None:
    """
    This function sends all data in TCP segment
    (multiple TCP packets if timeout else only one TCP packet).
    """

    if not timeout:
        socket.sendall(data)
        return None

    chunk = data[:30000]
    data = data[30000:]
    while chunk:
        socket.sendall(chunk)
        chunk = data[:30000]
        data = data[30000:]