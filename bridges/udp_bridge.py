#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    UDP bridge for ReverseShell.
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

'''
UDP bridge for ReverseShell.
'''

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = '''
UDP bridge for ReverseShell.
'''
__url__ = "https://github.com/mauricelambert/ReverseShell"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = '''
ReverseShell  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
'''
copyright = __copyright__
license = __license__

print(copyright)

from socket import socket, AF_INET, SOCK_DGRAM
from contextlib import suppress

use_timeout = True

address_server = ('127.0.0.1', 1337)
address_destination = ('127.0.0.1', 1338)

while True:
    with suppress(Exception):
        socket_server = socket(AF_INET, SOCK_DGRAM)
        socket_server.bind(address_server)
        socket_client = socket(AF_INET, SOCK_DGRAM)

        while True:
            data, address_client = socket_server.recvfrom(65535)
            socket_client.sendto(data, address_destination)
            data = socket_client.recv(65535)
            socket_server.sendto(data, address_client)

        socket_client.close()
        socket_server.close()